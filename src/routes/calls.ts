// src/routes/calls.ts
import express, { type RequestHandler } from 'express';
import { verifyJwt } from '../verifyJwt';
import { db } from '../firebase';
import { RtcTokenBuilder, RtcRole } from 'agora-access-token';
import fetch from 'node-fetch';
import { Storage, type File } from '@google-cloud/storage';
import { FieldValue } from 'firebase-admin/firestore';

export const callsRouter = express.Router();
callsRouter.use(verifyJwt);

// === ENV (fail fast where it matters) ===
const APP_ID = process.env.AGORA_APP_ID!;
const APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE!;
if (!APP_ID || !APP_CERTIFICATE) {
  console.warn('⚠️ Missing AGORA_APP_ID / AGORA_APP_CERTIFICATE');
}

// Agora Cloud Recording REST auth (Basic auth with customer id/secret)
const AGORA_REC_CUSTOMER_ID = process.env.AGORA_REC_CUSTOMER_ID || '';
const AGORA_REC_CUSTOMER_CERT = process.env.AGORA_REC_CUSTOMER_CERT || '';
if (!AGORA_REC_CUSTOMER_ID || !AGORA_REC_CUSTOMER_CERT) {
  console.warn('⚠️ Missing AGORA_REC_CUSTOMER_ID / AGORA_REC_CUSTOMER_CERT for Cloud Recording REST');
}

// Optional: acquire region; if invalid we omit and let Agora decide
const AGORA_REC_REGION = (process.env.AGORA_REC_REGION || '').toUpperCase();

const TOKEN_EXPIRATION_SECONDS = Number(process.env.AGORA_TOKEN_TTL || 3600);

// === Dedicated recorder UID (MUST NOT clash with real users) ===
const RECORDER_UID = String(process.env.AGORA_RECORDER_UID || '10001'); // numeric string, e.g. "10001"

// === Recording profile alignment ===
// Must match how your RTC channel is created by clients: 0 = Communication, 1 = Live Broadcast
const AGORA_RECORDING_CHANNEL_TYPE = Number(process.env.AGORA_RECORDING_CHANNEL_TYPE ?? 0);
// Recorder role used when generating the RTC token for the recorder
const RECORDER_ROLE =
  (process.env.AGORA_RECORDER_ROLE || 'PUBLISHER').toUpperCase() === 'SUBSCRIBER'
    ? RtcRole.SUBSCRIBER
    : RtcRole.PUBLISHER; // default PUBLISHER

// GCS bucket + prefixes
const GCS_BUCKET = process.env.GCS_BUCKET || '';
const GCS_PREFIX = process.env.GCS_PREFIX || 'calls';
const GCS_SIGN_URL_TTL_SECONDS = Number(process.env.GCS_SIGN_URL_TTL_SECONDS || 3600);

// GCS Interoperability (S3-compatible) keys for Agora → GCS writes
const GCS_INTEROP_ACCESS_KEY = process.env.GCS_INTEROP_ACCESS_KEY || '';
const GCS_INTEROP_SECRET_KEY = process.env.GCS_INTEROP_SECRET_KEY || '';
// MUST be present and a number for Agora validation (GCS ignores the value)
const GCS_REGION_CODE = Number(process.env.GCS_REGION_CODE ?? 0);

// AssemblyAI
const ASSEMBLYAI_API_KEY = process.env.ASSEMBLYAI_API_KEY || '';
const ASSEMBLYAI_WEBHOOK_SECRET = process.env.ASSEMBLYAI_WEBHOOK_SECRET || 'secret';

// Optional: archive transcripts
const ARCHIVE_TRANSCRIPTS_TO_GCS =
  String(process.env.ARCHIVE_TRANSCRIPTS_TO_GCS || 'false').toLowerCase() === 'true';
const TRANSCRIPTS_PREFIX = process.env.TRANSCRIPTS_PREFIX || 'transcripts';

// GCS client
const storage = new Storage();

// ========= Lock settings =========
const START_LOCK_TTL_MS = Number(process.env.REC_START_LOCK_TTL_MS || 30000); // 30s default
const STOP_LOCK_TTL_MS = Number(process.env.REC_STOP_LOCK_TTL_MS || 30000);   // stop lock
const SUBMIT_LOCK_TTL_MS = Number(process.env.TRANSCRIBE_SUBMIT_LOCK_TTL_MS || 30000); // submit lock

// === Helpers ===
function channelDocRef(channelName: string) {
  return db.collection('calls').doc(`chan_${channelName}`);
}

async function ensureCallDoc(channelName: string, participants: string[]) {
  const ref = channelDocRef(channelName);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) {
      tx.set(ref, {
        channelName,
        participants: Array.from(new Set(participants || [])),
        active: true,
        startedAt: Date.now(),
        lastSeenAt: Date.now(),
      });
    } else {
      const data = snap.data() || {};
      const merged = Array.from(new Set([...(data.participants || []), ...(participants || [])]));
      tx.set(ref, { participants: merged, lastSeenAt: Date.now() }, { merge: true });
    }
  });
}

function basicAuthHeader(id: string, secret: string) {
  const b64 = Buffer.from(`${id}:${secret}`).toString('base64');
  return `Basic ${b64}`;
}

// ========= Token =========

function hashToInt32(input: string): number {
  // FNV-1a 32-bit -> positive 31-bit
  let h = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    h ^= input.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  const pos = h & 0x7fffffff;
  return pos === 0 ? 1 : pos;
}

callsRouter.post('/token', async (req, res) => {
  try {
    const authUid = String((req as any).uid || '');
    const { channelName, uid } = (req.body || {}) as { channelName?: string; uid?: string | number };
    if (!channelName) return res.status(400).json({ error: 'Missing channelName' });

    let agoraUid: number;
    if (uid != null && /^\d+$/.test(String(uid))) {
      agoraUid = Number(uid);
    } else {
      // Deterministic numeric UID from auth uid
      agoraUid = hashToInt32(authUid);
    }

    const expireTs = Math.floor(Date.now() / 1000) + TOKEN_EXPIRATION_SECONDS;
    const token = RtcTokenBuilder.buildTokenWithUid(
      APP_ID,
      APP_CERTIFICATE,
      channelName,
      agoraUid,
      RtcRole.PUBLISHER,
      expireTs
    );

    return res.status(200).json({ token, expiresAt: expireTs * 1000, agoraUid, uid: String(agoraUid) });
  } catch (e) {
    console.error('❌ Failed to generate token', e);
    return res.status(500).json({ error: 'Failed to generate token' });
  }
});

// Build a token for the recorder UID (role configurable; default PUBLISHER)
function buildRecorderToken(channelName: string) {
  const expireTs = Math.floor(Date.now() / 1000) + TOKEN_EXPIRATION_SECONDS;
  const token = RtcTokenBuilder.buildTokenWithUid(
    APP_ID,
    APP_CERTIFICATE,
    channelName,
    Number(RECORDER_UID),
    RECORDER_ROLE,
    expireTs
  );
  return { token, expiresAt: expireTs * 1000 };
}

// ========= Call lifecycle =========
callsRouter.post('/start', async (req, res) => {
  try {
    const caller = (req as any).uid as string;
    const { channelName, participants = [] } = req.body || {};
    if (!channelName) return res.status(400).json({ error: 'Missing channelName' });

    await ensureCallDoc(channelName, [caller, ...participants]);

    // Best-effort: trigger icebreaker generation once at call setup so both clients see the same prompt.
    // Trigger early (fire-and-forget) before any early returns from recording flow.
    try {
      const base = process.env.API_BASE_URL || '';
      if (base) {
        const fetchDyn = (await import('node-fetch')).default as any;
        const url = `${base}/calls/${encodeURIComponent(channelName)}/icebreaker`;
        const auth = (req as any).headers?.authorization || '';
        (async () => {
          try {
            console.log('[ICEBREAKER] scheduling from /calls/start', { channelName, caller, hasAuth: !!auth });
            const r = await fetchDyn(url, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', Authorization: auth },
              body: '{}',
            });
            if (!r.ok) {
              const t = await r.text();
              console.warn('[ICEBREAKER] schedule non-200 from /calls/start', { status: r.status, body: t });
            }
          } catch (e: any) {
            console.warn('[ICEBREAKER] schedule error (ignored)', String(e?.message || e));
          }
        })();
      } else {
        console.warn('[ICEBREAKER] cannot schedule; missing API_BASE_URL');
      }
    } catch (e) {
      console.warn('[ICEBREAKER] scheduling block threw (ignored)', e);
    }

    // Auto-start recording with race-proof logic
    let lockId: string | null = null;
    try {
      if (!/^\d+$/.test(RECORDER_UID)) {
        return res.status(500).json({ error: 'Configured RECORDER_UID must be numeric' });
      }
      if (!AGORA_REC_CUSTOMER_ID || !AGORA_REC_CUSTOMER_CERT) {
        return res.status(500).json({ error: 'Missing Agora Cloud Recording REST credentials' });
      }
      if (!GCS_BUCKET || !GCS_INTEROP_ACCESS_KEY || !GCS_INTEROP_SECRET_KEY) {
        return res.status(500).json({ error: 'Missing GCS bucket or interoperability keys' });
      }

      // Fast path: already active?
      const ref = channelDocRef(channelName);
      const existingSnap = await ref.get();
      const existingRec = existingSnap.data()?.rec;
      if (existingRec?.sid && !existingRec?.stoppedAt) {
        return res.json({ ok: true, recording: { resourceId: existingRec.resourceId, sid: existingRec.sid, alreadyActive: true } });
      }

      try {
        lockId = await acquireStartLock(channelName, caller);
      } catch (e: any) {
        if (e?.message === 'ALREADY_ACTIVE') {
          const s2 = await ref.get();
          const r2 = s2.data()?.rec;
          return res.json({ ok: true, recording: { resourceId: r2?.resourceId, sid: r2?.sid, alreadyActive: true } });
        }
        if (e?.message === 'ALREADY_STARTING') {
          return res.status(202).json({ ok: true, recording: { starting: true } });
        }
        throw e;
      }

      const { segments, objectPathBase } = await buildRecordingPrefix(channelName);
      const { token: recorderToken } = buildRecorderToken(channelName);
      try {
        const { resourceId, sid } = await startRecordingToGCS(
          channelName,
          RECORDER_UID,
          segments,
          objectPathBase,
          recorderToken
        );
        return res.json({ ok: true, recording: { resourceId, sid } });
      } catch (err) {
        await ref.set({ rec: { startErrorAt: nowMs(), startError: String(err) } }, { merge: true });
        console.error('⚠️ Failed to auto-start recording at /calls/start', err);
        return res.json({ ok: true, recording: { started: false } });
      } finally {
        if (lockId) await releaseStartLock(channelName, lockId);
      }
    } catch (e) {
      console.error('❌ /calls/start recording block error', e);
      return res.json({ ok: true, recording: { started: false } });
    }

    // Best-effort: trigger icebreaker generation once at call setup so both clients see the same prompt.
    // Do not block the response; fire-and-forget with auth header.
    try {
      const base = process.env.API_BASE_URL || '';
      if (base) {
        const fetchDyn = (await import('node-fetch')).default as any;
        fetchDyn(`${base}/calls/${encodeURIComponent(channelName)}/icebreaker`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: req.headers.authorization || '',
          },
          body: '{}',
        }).catch((e: any) => {
          console.warn('⚠️ Failed to trigger icebreaker generation at start (ignored):', String(e?.message || e));
        });
      }
    } catch (e) {
      console.warn('⚠️ Error scheduling icebreaker generation (ignored):', e);
    }
  } catch (e) {
    console.error('❌ /calls/start error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// List active calls that include any member of the specified group
// GET /calls/active?groupId=abc123
callsRouter.get('/active', async (req, res) => {
  try {
    const groupId = String(req.query.groupId || '').trim();
    if (!groupId) return res.status(400).json({ error: 'Missing groupId' });

    // load group members (collect UIDs)
    const membersSnap = await db.collection('groups').doc(groupId).collection('members').get();
    const memberUids = new Set<string>();
    for (const m of membersSnap.docs) {
      const d = m.data() || {};
      const uid = String(d.uid || m.id || '').trim();
      if (uid) memberUids.add(uid);
    }

    // fetch recent active calls (filter server-side in app layer)
    const callsSnap = await db
      .collection('calls')
      .where('active', '==', true)
      .orderBy('startedAt', 'desc')
      .limit(200)
      .get();

    const now = Date.now();
    const rows: any[] = [];
    for (const doc of callsSnap.docs) {
      const data = doc.data() || {};
      const rawParts: any[] = Array.isArray((data as any).participants)
        ? (((data as any).participants as any[]) || [])
        : [];
      const participantsSet = new Set<string>(
        rawParts.map((x: any) => String(x ?? '')).filter((s: string) => s.length > 0)
      );
      const participants: string[] = Array.from(participantsSet);
      // include if any participant is in group
      const intersects = participants.some((p) => memberUids.has(p));
      if (!intersects) continue;
      const startedAt = Number(data.startedAt || 0);
      rows.push({
        channelName: String(data.channelName || String(doc.id).replace(/^chan_/, '')),
        participants,
        orgParticipants: participants.filter((p) => memberUids.has(p)),
        startedAt,
        durationMs: startedAt > 0 ? Math.max(0, now - startedAt) : null,
        lastSeenAt: Number(data.lastSeenAt || 0) || null,
        icebreaker: (data.icebreaker && data.icebreaker.text) ? String(data.icebreaker.text) : null,
      });
    }

    return res.json({ calls: rows });
  } catch (e) {
    console.error('❌ /calls/active error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// List recent ended calls for the current user
// GET /calls/history/me?limit=50
callsRouter.get('/history/me', async (req, res) => {
  try {
    const uid = (req as any).uid;
    const limitRaw = Number(req.query.limit ?? 50);
    const limit = isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 100) : 50;

    // Fetch calls where user was a participant
    // Note: Our calls collection has a 'participants' array field
    const callsSnap = await db
      .collection('calls')
      .where('participants', 'array-contains', uid)
      .where('active', '==', false)
      .orderBy('endedAt', 'desc')
      .limit(limit)
      .get();

    const rows: any[] = [];
    for (const doc of callsSnap.docs) {
      const data = doc.data() || {};
      const participants: string[] = Array.from(new Set(data.participants || []));
      const partnerUid = participants.find(p => p !== uid) || '';
      
      let partnerUsername = partnerUid;
      if (partnerUid) {
        const meta = await db.collection('user_metadata').doc(partnerUid).get();
        partnerUsername = meta.data()?.username || partnerUid;
      }

      rows.push({
        channelName: data.channelName,
        partnerUid,
        partnerUsername,
        startedAt: data.startedAt,
        endedAt: data.endedAt,
        durationSec: data.startedAt && data.endedAt ? Math.round((data.endedAt - data.startedAt) / 1000) : 0,
        transcription: data.transcription || null,
      });
    }

    return res.json({ calls: rows });
  } catch (e) {
    console.error('❌ /calls/history/me error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// List recent ended calls that included a member of the specified group
// GET /calls/history?groupId=abc123&limit=100
callsRouter.get('/history', async (req, res) => {
  try {
    const groupId = String(req.query.groupId || '').trim();
    const limitRaw = Number(req.query.limit ?? 100);
    const limit = isFinite(limitRaw) && limitRaw > 0 ? Math.min(limitRaw, 500) : 100;
    if (!groupId) return res.status(400).json({ error: 'Missing groupId' });

    // Group members
    const membersSnap = await db.collection('groups').doc(groupId).collection('members').get();
    const memberUids = new Set<string>();
    for (const m of membersSnap.docs) {
      const d = m.data() || {};
      const uid = String(d.uid || m.id || '').trim();
      if (uid) memberUids.add(uid);
    }

    // Fetch recent ended calls (active == false) by endedAt desc
    const callsSnap = await db
      .collection('calls')
      .where('active', '==', false)
      .orderBy('endedAt', 'desc')
      .limit(limit)
      .get();

    const rows: any[] = [];
    for (const doc of callsSnap.docs) {
      const data = doc.data() || {};
      const rawParts: any[] = Array.isArray((data as any).participants)
        ? (((data as any).participants as any[]) || [])
        : [];
      const participants = Array.from(
        new Set<string>(rawParts.map((x: any) => String(x ?? '')).filter((s: string) => s.length > 0))
      );
      const intersects = participants.some((p) => memberUids.has(p));
      if (!intersects) continue;

      const startedAt = Number(data.startedAt || 0);
      const endedAt = Number(data.endedAt || 0);
      const durationMs =
        startedAt > 0 && endedAt > 0 && endedAt >= startedAt ? endedAt - startedAt : null;

      rows.push({
        channelName: String(data.channelName || String(doc.id).replace(/^chan_/, '')),
        participants,
        orgParticipants: participants.filter((p) => memberUids.has(p)),
        startedAt: startedAt || null,
        endedAt: endedAt || null,
        durationMs,
        icebreaker: (data.icebreaker && data.icebreaker.text) ? String(data.icebreaker.text) : null,
      });
    }

    return res.json({ calls: rows });
  } catch (e) {
    console.error('❌ /calls/history error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

callsRouter.get('/:channelName/status', async (req, res) => {
  try {
    const { channelName } = req.params;
    const snap = await channelDocRef(channelName).get();
    if (!snap.exists) return res.json({ active: false });

    const data = snap.data() || {};
    return res.json({
      active: !!data.active,
      startedAt: data.startedAt || null,
      endedAt: data.endedAt || null,
      lastSeenAt: data.lastSeenAt || null,
      rec: data.rec || null,
      transcription: data.transcription || null,
    });
  } catch (e) {
    console.error('❌ /calls/:channelName/status error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

callsRouter.post('/:channelName/end', async (req, res) => {
  try {
    const ender = (req as any).uid as string;
    const { channelName } = req.params;
    const { reason } = req.body || {};
    const ref = channelDocRef(channelName);

    // Mark call inactive (idempotent)
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) return;
      const data = snap.data() || {};
      if (data.active === false) return;
      tx.set(
        ref,
        {
          active: false,
          endedAt: Date.now(),
          endedBy: ender,
          endReason: reason || 'ended',
          lastSeenAt: Date.now(),
        },
        { merge: true }
      );
    });

    // Stop recording once (stop lock)
    let stopLockId: string | null = null;
    try {
      stopLockId = await acquireStopLock(channelName, ender);
      const snap = await ref.get();
      const rec = snap.data()?.rec;

      if (!rec?.resourceId || !rec?.sid) {
        // nothing to stop (or already cleared)
      } else {
        const recorderUid: string = String(rec.recorderUid || RECORDER_UID);
        if (/^\d+$/.test(recorderUid)) {
          try {
            await stopRecording(rec.resourceId, rec.sid, channelName, recorderUid);
          } catch (e) {
            console.warn('⚠️ stopRecording failed (ignored):', e);
          }
          await ref.set({ rec: { ...rec, stoppedAt: Date.now() } }, { merge: true });
        }
      }
    } catch (e: any) {
      if (e?.message === 'ALREADY_STOPPED') {
        // already done
      } else if (e?.message === 'ALREADY_STOPPING') {
        // someone else is stopping
      } else {
        console.warn('⚠️ Failed to acquire stop lock:', e);
      }
    } finally {
      if (stopLockId) await releaseStopLock(channelName, stopLockId);
    }

    // Schedule transcription exactly once
    let shouldSchedule = false;
    await db.runTransaction(async (tx) => {
      const snap = await tx.get(ref);
      if (!snap.exists) return;
      const data = snap.data() || {};
      const tr = data.transcription || {};
      const status = String(tr.status || '');

      if (tr.submitScheduledAt) return; // already scheduled
      if (['submitted', 'processing', 'completed'].includes(status) && tr.id) return; // already submitted

      shouldSchedule = true;
      tx.set(
        ref,
        { transcription: { ...tr, submitScheduledAt: Date.now(), submitScheduledBy: ender } },
        { merge: true }
      );
    });

    if (shouldSchedule) {
      setTimeout(async () => {
        try {
          const base = process.env.API_BASE_URL || '';
          if (!base) return;
          const fetchDyn = (await import('node-fetch')).default as any;
          await fetchDyn(`${base}/calls/${encodeURIComponent(channelName)}/transcribe`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', Authorization: req.headers.authorization || '' },
            body: '{}',
          });
        } catch (e) {
          console.warn('⚠️ Failed to submit transcription at call end', e);
        }
      }, 30_000);
    }

    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ /calls/:channelName/end error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// ========= Icebreaker (GPT-backed with fallback) =========
callsRouter.post('/:channelName/icebreaker', async (req, res) => {
  try {
    const authUid = String((req as any).uid || '');
    const { channelName } = req.params;
    if (!channelName) return res.status(400).json({ error: 'Missing channelName' });

    console.log('[ICEBREAKER] request', { channelName, requester: authUid });
    const startTs = Date.now();

    const ref = channelDocRef(channelName);
    const snap = await ref.get();
    const data = snap.data() || {};

    // If already generated, return it
    const existingText = (data as any)?.icebreaker?.text;
    if (existingText) {
      const existingSource = (data as any)?.icebreaker?.source || 'cached';
      console.log('[ICEBREAKER] already present', { channelName, source: existingSource });
      return res.json({ text: String(existingText), source: String(existingSource) });
    }

    let participants: string[] = Array.from(
      new Set((data.participants || []).map((x: any) => String(x || '').trim()).filter((s: string) => s.length > 0))
    );

    // Wait briefly (up to ~6.4s) for both participants to be recorded
    if (participants.length < 2) {
      for (let i = 0; i < 8 && participants.length < 2; i++) {
        console.log('[ICEBREAKER] waiting for participants', { channelName, count: participants.length, attempt: i + 1 });
        await delay(800);
        const again = await ref.get();
        const d2 = again.data() || {};
        participants = Array.from(
          new Set((d2.participants || []).map((x: any) => String(x || '').trim()).filter((s: string) => s.length > 0))
        );
      }
    }

    if (participants.length === 0) {
      // Persist fallback and return
      const text = 'What do you do for fun?';
      await ref.set(
        { icebreaker: { text, source: 'fallback_no_participants', generatedAt: Date.now(), requestedBy: authUid } },
        { merge: true }
      );
      return res.json({ text, source: 'fallback', reason: 'no_participants' });
    }

    let a = participants[0];
    let b = participants.find((p) => p !== a) || participants[0];

    // Load bios for both
    const [aMeta, bMeta] = await Promise.all([
      db.collection('user_metadata').doc(a).get(),
      db.collection('user_metadata').doc(b).get(),
    ]);
    const aBio = (aMeta.data()?.bioResponses as Record<string, unknown> | undefined) || {};
    const bBio = (bMeta.data()?.bioResponses as Record<string, unknown> | undefined) || {};
    console.log('[ICEBREAKER] bios loaded', {
      channelName,
      a,
      b,
      aFields: Object.keys(aBio).length,
      bFields: Object.keys(bBio).length,
    });

    // Try GPT with a firm timeout (9.5s here; client also uses 10s)
    const key = process.env.OPENAI_API_KEY || '';
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 9500);

    let text: string | null = null;
    let source = 'fallback';

    if (key) {
      try {
        console.log('[ICEBREAKER] calling OpenAI', { channelName });
        const messages = [
          {
            role: 'system',
            content:
              "You are Howdy's friendly icebreaker assistant. Output EXACTLY ONE short, natural question. If there is a clear shared topic between the two users' bios, ask about that topic. Keep it safe and PII-free.",
          },
          {
            role: 'user',
            content:
              `User A bioResponses (JSON): ${JSON.stringify(aBio)}\nUser B bioResponses (JSON): ${JSON.stringify(
                bBio
              )}\n\nTask: Find a shared hobby/interest if possible and ask one friendly question about it. If there is no meaningful overlap, respond with exactly: What do you do for fun?`,
          },
        ];
        const payload = {
          model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
          temperature: 0.6,
          max_tokens: 50,
          messages,
        };
        const r = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            Authorization: `Bearer ${key}`,
            'Content-Type': 'application/json',
            ...(process.env.OPENAI_ORG ? { 'OpenAI-Organization': process.env.OPENAI_ORG as string } : {}),
            ...(process.env.OPENAI_PROJECT ? { 'OpenAI-Project': process.env.OPENAI_PROJECT as string } : {}),
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });
        clearTimeout(timer);
        if (r.ok) {
          const j: any = await r.json();
          const content = j?.choices?.[0]?.message?.content?.toString()?.trim();
          if (content && content.length > 0) {
            text = content;
            source = 'gpt';
            console.log('[ICEBREAKER] GPT success', { channelName, latencyMs: Date.now() - startTs });
          }
        } else {
          console.warn('⚠️ OpenAI icebreaker API error', await r.text());
        }
      } catch (e) {
        clearTimeout(timer);
        console.warn('⚠️ OpenAI icebreaker request failed or timed out; falling back', e);
      }
    } else {
      clearTimeout(timer);
    }

    if (!text || !text.trim()) {
      text = 'What do you do for fun?';
      source = 'fallback';
      console.log('[ICEBREAKER] using fallback', { channelName, latencyMs: Date.now() - startTs });
    }

    await ref.set(
      {
        icebreaker: {
          text,
          source,
          generatedAt: Date.now(),
          requestedBy: authUid,
          a: a,
          b: b,
        },
      },
      { merge: true }
    );

    return res.json({ text, source });
  } catch (e) {
    console.error('❌ /calls/:channelName/icebreaker error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// ========= Prefix building (safe, human-readable) =========
function sanitizeToken(raw: string): string {
  let s = String(raw || '');
  s = s.replace(/_/g, '');
  s = s.replace(/[^A-Za-z0-9]+/g, '');
  if (s.length === 0) s = 'unknown';
  if (s.length > 120) s = s.slice(0, 120);
  return s;
}

async function buildRecordingPrefix(channelName: string): Promise<{ segments: string[]; objectPathBase: string }> {
  const baseParts = String(GCS_PREFIX || 'calls').split('/').filter(Boolean).map(sanitizeToken).filter(Boolean);

  let a = 'unknown', b = 'unknown';
  try {
    const snap = await channelDocRef(channelName).get();
    const parts: string[] = Array.from(new Set([...(snap.data()?.participants || [])]))
      .map((x: any) => String(x || '').trim())
      .filter((x: string) => x.length > 0);
    // Always use alphabetically sorted document IDs so the prefix is stable
    if (parts.length >= 2) {
      const sortedAll = parts.slice().sort((s1, s2) => s1.localeCompare(s2));
      a = sortedAll[0];
      b = sortedAll[1];
    } else if (parts.length === 1) {
      a = parts[0];
      b = 'unknown';
    }
  } catch {}

  const aSafe = sanitizeToken(a);
  const bSafe = sanitizeToken(b);
  const chanSafe = sanitizeToken(channelName);

  let label = `${aSafe}XXX${bSafe}XXX${chanSafe}`;
  if (label.length > 120) label = label.slice(0, 120);

  const segments = [...baseParts, label];
  const objectPathBase = `${segments.join('/')}/`;
  return { segments, objectPathBase };
}

// ========= Agora Cloud Recording (→ GCS) =========
function validAcquireRegionOrUndefined(raw: string): string | undefined {
  const allowed = new Set(['NA', 'EU', 'AP', 'CN', 'SA', 'OC', 'AF']);
  const v = (raw || '').toUpperCase();
  return allowed.has(v) ? v : undefined;
}

async function acquireRecordingResource(channelName: string, uid: string) {
  const url = `https://api.agora.io/v1/apps/${APP_ID}/cloud_recording/acquire`;

  const clientRequest: any = {};
  const region = validAcquireRegionOrUndefined(AGORA_REC_REGION);
  if (region) clientRequest.region = region;

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: basicAuthHeader(AGORA_REC_CUSTOMER_ID, AGORA_REC_CUSTOMER_CERT),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ cname: channelName, uid, clientRequest }),
  });

  if (!resp.ok) {
    throw new Error(`Acquire failed ${resp.status} \n${await resp.text()}`);
  }
  return resp.json() as Promise<{ resourceId: string }>;
}

async function startRecordingToGCS(
  channelName: string,
  uid: string,
  fileNamePrefixSegments: string[],
  objectPathBaseForFirestore: string,
  recorderToken: string
) {
  const { resourceId } = await acquireRecordingResource(channelName, uid);

  const url = `https://api.agora.io/v1/apps/${APP_ID}/cloud_recording/resourceid/${resourceId}/mode/mix/start`;

  // Explicit config to match your RTC profile and subscribe behaviour
  const recordingConfig = {
    maxIdleTime: 120,
    streamTypes: 2,                // audio + video (OK even if only audio published)
    audioProfile: 1,
    channelType: AGORA_RECORDING_CHANNEL_TYPE, // 0: COMMUNICATION, 1: LIVE
    subscribeUidGroup: 0,          // subscribe to all UIDs automatically
    transcodingConfig: {
      width: 640,
      height: 360,
      fps: 15,
      bitrate: 600,
      mixedVideoLayout: 1,
      backgroundColor: '#000000',
    },
  };

  // ✅ Ask Agora to write MP4 (and HLS due to GCS quirk noted)
  // DON'T REMOVE HLS IT IS A CURRENT BUG WITH USING GCP FOR AGORA STORAGE
  const recordingFileConfig = { avFileType: ['mp4', 'hls'] };

  const storageConfig = {
    vendor: 6, // Google Cloud Storage
    region: GCS_REGION_CODE, // GCS ignores this value; Agora requires a number
    bucket: GCS_BUCKET,
    accessKey: GCS_INTEROP_ACCESS_KEY,
    secretKey: GCS_INTEROP_SECRET_KEY,
    fileNamePrefix: fileNamePrefixSegments,
  };

  console.log(
    'Sending for record to Agora',
    channelName,
    uid,
    storageConfig.vendor,
    storageConfig.region,
    storageConfig.bucket,
    '[fileNamePrefix]',
    fileNamePrefixSegments
  );

  const body = {
    cname: channelName,
    uid,
    clientRequest: {
      token: recorderToken, // 🔑 REQUIRED when App Certificate/token auth is enabled
      recordingConfig,
      recordingFileConfig,
      storageConfig,
    },
  };

  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: basicAuthHeader(AGORA_REC_CUSTOMER_ID, AGORA_REC_CUSTOMER_CERT),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  if (!resp.ok) {
    const t = await resp.text();
    console.error(
      '❌ Agora start failed. storage.vendor=%s region=%s bucket=%s prefix=%s',
      storageConfig.vendor,
      storageConfig.region,
      storageConfig.bucket,
      fileNamePrefixSegments.join('/')
    );
    throw new Error(`Start failed ${resp.status} \n${t}`);
  }

  const data = (await resp.json()) as any;
  console.log('✅ Agora start OK', { channelName, resourceId, sid: data?.sid });

  await channelDocRef(channelName).set(
    {
      rec: {
        resourceId,
        sid: data.sid as string,
        bucket: GCS_BUCKET,
        objectPathBase: objectPathBaseForFirestore,
        recorderUid: String(uid), // persist the numeric UID used to start
        startedAt: Date.now(),
      },
    },
    { merge: true }
  );

  return { resourceId, sid: data.sid as string };
}

async function stopRecording(resourceId: string, sid: string, channelName: string, uid: string) {
  const url = `https://api.agora.io/v1/apps/${APP_ID}/cloud_recording/resourceid/${resourceId}/sid/${sid}/mode/mix/stop`;
  console.log('Sending for stop to Agora', url, channelName, uid);
  const resp = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: basicAuthHeader(AGORA_REC_CUSTOMER_ID, AGORA_REC_CUSTOMER_CERT),
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ cname: channelName, uid, clientRequest: {} }),
  });
  if (!resp.ok) {
    throw new Error(`Stop failed ${resp.status} \n${await resp.text()}`);
  }
  const data = await resp.json();
  console.log('✅ Agora stop OK', { channelName, resourceId, sid, data });
  return data;
}

async function queryRecording(resourceId: string, sid: string, channelName: string) {
  const url = `https://api.agora.io/v1/apps/${APP_ID}/cloud_recording/resourceid/${resourceId}/sid/${sid}/mode/mix/query`;
  const resp = await fetch(url, {
    method: 'GET',
    headers: { Authorization: basicAuthHeader(AGORA_REC_CUSTOMER_ID, AGORA_REC_CUSTOMER_CERT) },
  });
  if (!resp.ok) {
    const t = await resp.text();
    throw new Error(`Query failed ${resp.status} \n${t}`);
  }
  const data = await resp.json();
  console.log('ℹ️ Agora query', { channelName, resourceId, sid, data });
  return data;
}

// ========= Start/Stop/Submit locks =========
function nowMs() {
  return Date.now();
}

async function acquireStartLock(channelName: string, ownerUid: string): Promise<string> {
  const ref = channelDocRef(channelName);
  const lockId = Math.random().toString(36).slice(2);
  const now = nowMs();

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? (snap.data() || {}) : {};

    const rec = data.rec || {};

    // If already active, don't start again
    if (rec.sid && !rec.stoppedAt) {
      throw new Error('ALREADY_ACTIVE');
    }

    // Respect an in-flight start if still within TTL
    const lock = rec.startLock;
    const lockFresh = lock && now - (lock.at || 0) < START_LOCK_TTL_MS && !rec.sid;
    if (lockFresh) {
      throw new Error('ALREADY_STARTING');
    }

    // Ensure doc exists and acquire lock
    const base: any = {};
    if (!snap.exists) {
      base.channelName = channelName;
      base.active = true;
      base.startedAt = now;
      base.lastSeenAt = now;
    }

    tx.set(ref, base, { merge: true });
    tx.update(ref, { 'rec.startLock': { id: lockId, owner: ownerUid, at: now } });
  });

  return lockId;
}

async function releaseStartLock(channelName: string, lockId: string) {
  const ref = channelDocRef(channelName);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) return;
    const rec = snap.data()?.rec || {};
    if (rec.startLock?.id === lockId) {
      tx.update(ref, { 'rec.startLock': FieldValue.delete() });
    }
  });
}

async function acquireStopLock(channelName: string, ownerUid: string): Promise<string> {
  const ref = channelDocRef(channelName);
  const lockId = Math.random().toString(36).slice(2);
  const now = nowMs();

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new Error('NO_CALL_DOC');

    const data = snap.data() || {};
    const rec = data.rec || {};

    if (rec.stoppedAt) throw new Error('ALREADY_STOPPED');

    const lock = rec.stopLock;
    const lockFresh = lock && now - (lock.at || 0) < STOP_LOCK_TTL_MS;
    if (lockFresh) throw new Error('ALREADY_STOPPING');

    tx.set(ref, { rec: { ...rec, stopLock: { id: lockId, owner: ownerUid, at: now } } }, { merge: true });
  });

  return lockId;
}

async function releaseStopLock(channelName: string, lockId: string) {
  const ref = channelDocRef(channelName);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) return;
    const data = snap.data() || {};
    const rec = data.rec || {};
    if (rec.stopLock?.id === lockId) {
      tx.update(ref, { 'rec.stopLock': FieldValue.delete() });
    }
  });
}

async function acquireSubmitLock(channelName: string, ownerUid: string): Promise<string> {
  const ref = channelDocRef(channelName);
  const lockId = Math.random().toString(36).slice(2);
  const now = nowMs();

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) throw new Error('NO_CALL_DOC');

    const data = snap.data() || {};
    const tr = data.transcription || {};

    // Already submitted/processing/completed? Don't acquire.
    const status = String(tr.status || '');
    if (['submitted', 'processing', 'completed'].includes(status) && tr.id) {
      throw new Error('ALREADY_SUBMITTED');
    }

    const lock = tr.submitLock;
    const lockFresh = lock && now - (lock.at || 0) < SUBMIT_LOCK_TTL_MS;
    if (lockFresh) throw new Error('ALREADY_SUBMITTING');

    tx.set(ref, { transcription: { ...tr, submitLock: { id: lockId, owner: ownerUid, at: now } } }, { merge: true });
  });

  return lockId;
}

async function releaseSubmitLock(channelName: string, lockId: string) {
  const ref = channelDocRef(channelName);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) return;
    const tr = (snap.data() || {}).transcription || {};
    if (tr.submitLock?.id === lockId) {
      tx.update(ref, { 'transcription.submitLock': FieldValue.delete() });
    }
  });
}

// START recording (manual endpoint if you ever call it)
callsRouter.post('/:channelName/record/start', async (req, res) => {
  const authUid = String((req as any).uid || '');
  const { channelName } = req.params;

  let lockId: string | null = null;

  try {
    if (!/^\d+$/.test(RECORDER_UID)) {
      return res.status(500).json({ error: 'Configured RECORDER_UID must be numeric' });
    }
    if (!AGORA_REC_CUSTOMER_ID || !AGORA_REC_CUSTOMER_CERT) {
      return res.status(500).json({ error: 'Missing Agora Cloud Recording REST credentials' });
    }
    if (!GCS_BUCKET || !GCS_INTEROP_ACCESS_KEY || !GCS_INTEROP_SECRET_KEY) {
      return res.status(500).json({ error: 'Missing GCS bucket or interoperability keys' });
    }

    // Fast path: already active?
    const ref = channelDocRef(channelName);
    const existingSnap = await ref.get();
    const existingRec = existingSnap.data()?.rec;
    if (existingRec?.sid && !existingRec?.stoppedAt) {
      console.log('ℹ️ Recording already active for', channelName, 'sid=', existingRec.sid);
      return res.json({ ok: true, resourceId: existingRec.resourceId, sid: existingRec.sid, alreadyActive: true });
    }

    // Acquire lock (race-proof)
    try {
      lockId = await acquireStartLock(channelName, authUid);
    } catch (e: any) {
      if (e?.message === 'ALREADY_ACTIVE') {
        const s2 = await ref.get();
        const r2 = s2.data()?.rec;
        return res.json({ ok: true, resourceId: r2?.resourceId, sid: r2?.sid, alreadyActive: true });
      }
      if (e?.message === 'ALREADY_STARTING') {
        console.log('ℹ️ Another instance is starting recording for', channelName);
        return res.status(202).json({ ok: true, starting: true });
      }
      throw e;
    }

    // Proceed to start (single winner past this point)
    const { segments, objectPathBase } = await buildRecordingPrefix(channelName);
    const { token: recorderToken } = buildRecorderToken(channelName);

    try {
      const { resourceId, sid } = await startRecordingToGCS(
        channelName,
        RECORDER_UID, // dedicated recorder UID
        segments,
        objectPathBase,
        recorderToken // 🔑 pass token
      );

      return res.json({ ok: true, resourceId, sid });
    } catch (err) {
      await ref.set({ rec: { startErrorAt: nowMs(), startError: String(err) } }, { merge: true });
      throw err;
    } finally {
      if (lockId) {
        await releaseStartLock(channelName, lockId);
      }
    }
  } catch (e) {
    console.error('❌ record/start error', e);
    return res.status(500).json({ error: 'Failed to start recording' });
  }
});

// STOP recording (idempotent; lock-aware)
callsRouter.post('/:channelName/record/stop', async (req, res) => {
  try {
    const { channelName } = req.params;
    const ref = channelDocRef(channelName);

    let rec: any = (await ref.get()).data()?.rec;
    if (!rec?.resourceId || !rec?.sid) {
      return res.status(400).json({ error: 'No active recording for this channel' });
    }
    if (rec?.stoppedAt) {
      return res.json({ ok: true, alreadyStopped: true });
    }

    let stopLockId: string | null = null;
    try {
      stopLockId = await acquireStopLock(channelName, String((req as any).uid || 'system'));
    } catch (e: any) {
      if (e?.message === 'ALREADY_STOPPED') {
        return res.json({ ok: true, alreadyStopped: true });
      }
      if (e?.message === 'ALREADY_STOPPING') {
        return res.status(202).json({ ok: true, stopping: true });
      }
      throw e;
    }

    rec = (await ref.get()).data()?.rec;
    const recorderUid: string = String(rec?.recorderUid || RECORDER_UID);
    if (!/^\d+$/.test(recorderUid)) {
      await releaseStopLock(channelName, stopLockId);
      return res.status(500).json({ error: 'Invalid recorderUid stored for this call' });
    }

    await stopRecording(rec.resourceId, rec.sid, channelName, recorderUid);
    await ref.set({ rec: { ...rec, stoppedAt: Date.now() } }, { merge: true });

    await releaseStopLock(channelName, stopLockId);
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ record/stop error', e);
    return res.status(500).json({ error: 'Failed to stop recording' });
  }
});

// QUERY recording status (debug/diagnostics)
callsRouter.get('/:channelName/record/status', async (req, res) => {
  try {
    const { channelName } = req.params;
    const snap = await channelDocRef(channelName).get();
    const rec = snap.data()?.rec;
    if (!rec?.resourceId || !rec?.sid) {
      return res.status(404).json({ error: 'No active recording for this channel (no resourceId/sid)' });
    }
    const status = await queryRecording(rec.resourceId, rec.sid, channelName);
    return res.json({ ok: true, status, rec });
  } catch (e: any) {
    console.error('❌ record/status error', e);
    return res.status(500).json({ error: 'Failed to query recording status', detail: String(e?.message || e) });
  }
});

// ========= GCS signed URL utilities =========
// Only single-file audio/video types for AAI; avoid .m3u8/.ts
const AUDIO_EXT_RE = /\.(m4a|aac|wav|mp3|mp4)$/i;
const MP4_RE = /\.mp4$/i;

async function listLatestFileUnderPrefix(
  bucketName: string,
  prefixesToTry: string[],
  preferMp4 = true
): Promise<File | null> {
  const bucket = storage.bucket(bucketName);

  for (const prefix of prefixesToTry) {
    const [files] = await bucket.getFiles({ prefix, autoPaginate: false });

    const audioish = files.filter((f) => AUDIO_EXT_RE.test(f.name));
    if (!audioish.length) continue;

    const withMeta = await Promise.all(
      audioish.map(async (f) => {
        const [md] = await f.getMetadata();
        const updated = new Date(md.updated || md.timeCreated || Date.now());
        const size = Number(md.size || 0);
        return { f, updated, size };
      })
    );

    withMeta.sort((a, b) => b.updated.getTime() - a.updated.getTime() || b.size - a.size);

    if (preferMp4) {
      const mp4 = withMeta.find((x) => MP4_RE.test(x.f.name));
      if (mp4) return mp4.f;
    }
    return withMeta[0]?.f ?? null;
  }

  return null;
}

function delay(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

// Try ~50s to catch finalized MP4; then fall back to newest audio
async function waitForLatestMp4(
  bucketName: string,
  prefixesToTry: string[],
  attempts = 7,
  delayMs = 7000
): Promise<File | null> {
  for (let i = 0; i < attempts; i++) {
    const f = await listLatestFileUnderPrefix(bucketName, prefixesToTry, true);
    if (f && MP4_RE.test(f.name)) return f;
    if (i < attempts - 1) await delay(delayMs);
  }
  return listLatestFileUnderPrefix(bucketName, prefixesToTry, false);
}

async function signedReadUrl(file: File, ttlSeconds = GCS_SIGN_URL_TTL_SECONDS) {
  const [url] = await file.getSignedUrl({
    version: 'v4',
    action: 'read',
    expires: Date.now() + ttlSeconds * 1000,
  });
  return url;
}

// List candidate recording objects (debug)
callsRouter.get('/:channelName/recordings', async (req, res) => {
  try {
    const { channelName } = req.params;
    const snap = await channelDocRef(channelName).get();
    const rec = snap.data()?.rec;

    if (!rec?.bucket) return res.status(404).json({ error: 'No recording metadata on call doc' });

    const prefixes: string[] = [String(rec.objectPathBase || '')];

    const recomputed = await buildRecordingPrefix(channelName);
    if (recomputed.objectPathBase && recomputed.objectPathBase !== prefixes[0]) {
      prefixes.push(recomputed.objectPathBase);
    }

    const bucket = storage.bucket(rec.bucket);
    const [files] = await bucket.getFiles({ prefix: prefixes[0], autoPaginate: false });

    return res.json({
      bucket: rec.bucket,
      triedPrefixes: prefixes,
      files: files.map((f) => f.name),
    });
  } catch (e) {
    console.error('❌ list recordings error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// Signed URL for newest audio-like file (for AAI or manual download)
callsRouter.get('/:channelName/recording-url', async (req, res) => {
  try {
    const { channelName } = req.params;
    const snap = await channelDocRef(channelName).get();
    const rec = snap.data()?.rec;

    if (!rec?.bucket) return res.status(404).json({ error: 'No recording metadata on call doc' });

    const prefixes: string[] = [String(rec.objectPathBase || '')];
    const recomputed = await buildRecordingPrefix(channelName);
    if (recomputed.objectPathBase && recomputed.objectPathBase !== prefixes[0]) {
      prefixes.push(recomputed.objectPathBase);
    }

    const file = await listLatestFileUnderPrefix(rec.bucket, prefixes, true);
    if (!file) return res.status(404).json({ error: 'No recording files found yet' });

    const url = await signedReadUrl(file);
    return res.json({ bucket: rec.bucket, object: file.name, url, expiresIn: GCS_SIGN_URL_TTL_SECONDS });
  } catch (e) {
    console.error('❌ signed url error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// ========= AssemblyAI submission (idempotent) =========
callsRouter.post('/:channelName/transcribe', async (req, res) => {
  try {
    if (!ASSEMBLYAI_API_KEY) {
      return res.status(500).json({ error: 'Missing ASSEMBLYAI_API_KEY' });
    }

    const { channelName } = req.params;
    console.log('🔊 channelName:', channelName);
    const ref = channelDocRef(channelName);
    const callDoc = await ref.get();
    const data = callDoc.data() || {};
    const rec = data.rec;

    // Already submitted/processing/completed?
    const tr = data.transcription || {};
    const status = String(tr.status || '');
    if (['submitted', 'processing', 'completed'].includes(status) && tr.id) {
      return res.json({ ok: true, alreadySubmitted: true, id: tr.id });
    }

    // Acquire submit lock
    let submitLockId: string | null = null;
    try {
      submitLockId = await acquireSubmitLock(channelName, String((req as any).uid || 'system'));
    } catch (e: any) {
      if (e?.message === 'ALREADY_SUBMITTED') {
        const latest = (await ref.get()).data()?.transcription || {};
        return res.json({ ok: true, alreadySubmitted: true, id: latest.id });
      }
      if (e?.message === 'ALREADY_SUBMITTING') {
        return res.status(202).json({ ok: true, submitting: true });
      }
      throw e;
    }

    if (!rec?.bucket) {
      await releaseSubmitLock(channelName, submitLockId!);
      return res.status(400).json({ error: 'No recording info on call doc' });
    }

    const prefixes: string[] = [String(rec.objectPathBase || '')];
    const recomputed = await buildRecordingPrefix(channelName);
    if (recomputed.objectPathBase && recomputed.objectPathBase !== prefixes[0]) {
      prefixes.push(recomputed.objectPathBase);
    }

    // Wait briefly for MP4 to finalize; then fall back to any audio-like file
    const file = await waitForLatestMp4(rec.bucket, prefixes);
    if (!file) {
      await releaseSubmitLock(channelName, submitLockId!);
      return res.status(404).json({ error: 'Recording file not found (yet). Try again shortly.' });
    }

    const signedUrl = await signedReadUrl(file);

    // use the public webhook base (from ngrok locally) to receive webhooks
    console.log('🔊 PUBLIC_BASE_URL:', process.env.PUBLIC_BASE_URL);
    const webhookUrlBase = process.env.PUBLIC_BASE_URL || process.env.API_BASE_URL || '';
    const webhookUrl = `${webhookUrlBase}/webhooks/assemblyai?channel=${encodeURIComponent(channelName)}`;

    const aaiResp = await fetch('https://api.assemblyai.com/v2/transcript', {
      method: 'POST',
      headers: {
        Authorization: ASSEMBLYAI_API_KEY,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        audio_url: signedUrl,
        punctuate: true,
        speaker_labels: true,
        webhook_url: webhookUrl,
        webhook_auth_header_name: 'X-AI-Signature',
        webhook_auth_header_value: ASSEMBLYAI_WEBHOOK_SECRET,
        // Optional: choose a speech model if you want
        // speech_model: 'universal'
      }),
    });

    if (!aaiResp.ok) {
      const t = await aaiResp.text();
      await releaseSubmitLock(channelName, submitLockId!);
      return res.status(502).json({ error: `AssemblyAI submit failed ${aaiResp.status}: ${t}` });
    }

    const submitted = await aaiResp.json();
    await ref.set(
      { transcription: { id: submitted.id, status: 'submitted', submittedAt: Date.now() } },
      { merge: true }
    );
    await releaseSubmitLock(channelName, submitLockId!);

    return res.json({ ok: true, id: submitted.id });
  } catch (e) {
    console.error('❌ /transcribe error', e);
    return res.status(500).json({ error: 'Failed to submit transcription' });
  }
});

// ========= Helpers for transcript archiving =========
async function saveStringToGcs(
  bucketName: string,
  objectName: string,
  contents: string,
  contentType = 'text/plain; charset=utf-8'
) {
  const file = storage.bucket(bucketName).file(objectName);
  await file.save(contents, { resumable: false, contentType, public: false });
  return { bucket: bucketName, object: objectName };
}

async function fetchAaiJson(transcriptId: string): Promise<any> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${transcriptId}`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY },
  });
  if (!r.ok) throw new Error(`AAI get transcript ${transcriptId} failed ${r.status}: ${await r.text()}`);
  return r.json();
}

async function fetchAaiText(transcriptId: string): Promise<string> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${transcriptId}`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY, Accept: 'text/plain' },
  });
  if (!r.ok) throw new Error(`AAI get text ${transcriptId} failed ${r.status}: ${await r.text()}`);
  return r.text();
}

async function fetchAaiSrt(transcriptId: string): Promise<string> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${transcriptId}/srt`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY },
  });
  if (!r.ok) throw new Error(`AAI get srt ${transcriptId} failed ${r.status}: ${await r.text()}`);
  return r.text();
}

async function fetchAaiVtt(transcriptId: string): Promise<string> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${transcriptId}/vtt`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY },
  });
  if (!r.ok) throw new Error(`AAI get vtt ${transcriptId} failed ${r.status}: ${await r.text()}`);
  return r.text();
}

// ========= Webhook (hardened) =========
export const assemblyAiWebhookHandler: RequestHandler = async (req, res) => {
  try {
    const sig = String(req.header('X-AI-Signature') || '');
    if (sig !== ASSEMBLYAI_WEBHOOK_SECRET) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    const channel = String(req.query.channel || '');
    if (!channel) return res.status(400).json({ error: 'Missing channel' });

    const payload: any = req.body || {};
    const status = String(payload.status ?? '');

    // Normalize transcript ID
    const transcriptIdRaw = payload.id ?? payload.transcript_id ?? payload.transcriptId ?? null;
    const transcriptId = transcriptIdRaw != null ? String(transcriptIdRaw) : null;

    // Read current doc to compare IDs (ignore foreign/duplicate jobs)
    const callSnap = await channelDocRef(channel).get();
    const callData = callSnap.data() || {};
    const currentTr = callData.transcription || {};
    const currentId: string | null = currentTr.id || null;

    if (transcriptId && currentId && transcriptId !== currentId) {
      await channelDocRef(channel).set(
        { transcription: { duplicates: FieldValue.arrayUnion(transcriptId), updatedAt: Date.now() } },
        { merge: true }
      );
      return res.json({ ok: true, ignored: true });
    }

    const baseUpdate: Record<string, any> = { status: status || 'unknown', updatedAt: Date.now() };
    if (transcriptId) baseUpdate.id = transcriptId;

    if (status === 'completed') {
      const rec = callData.rec || {};
      const bucketForArchive = String(rec.bucket || GCS_BUCKET || '');

      await channelDocRef(channel).set(
        { transcription: { ...baseUpdate, text: payload.text ?? null, summary: payload.summary ?? null, completedAt: Date.now() } },
        { merge: true }
      );

      if (ARCHIVE_TRANSCRIPTS_TO_GCS && bucketForArchive && transcriptId) {
        try {
          const [fullJson, plainText, srtText, vttText] = await Promise.all([
            fetchAaiJson(transcriptId),
            fetchAaiText(transcriptId),
            fetchAaiSrt(transcriptId),
            fetchAaiVtt(transcriptId),
          ]);

          // Prefer saving alongside the call recording
          const recBase: string | undefined = typeof rec.objectPathBase === 'string' ? rec.objectPathBase : undefined;

          const base = recBase
            ? `${recBase.replace(/\/$/, '')}/transcripts/${transcriptId}`
            : `${TRANSCRIPTS_PREFIX}/${encodeURIComponent(channel)}/${transcriptId}`;

          const jsonPath = `${base}/transcript.json`;
          const txtPath = `${base}/transcript.txt`;
          const srtPath = `${base}/transcript.srt`;
          const vttPath = `${base}/transcript.vtt`;

          await Promise.all([
            saveStringToGcs(bucketForArchive, jsonPath, JSON.stringify(fullJson, null, 2), 'application/json'),
            saveStringToGcs(bucketForArchive, txtPath, plainText, 'text/plain; charset=utf-8'),
            saveStringToGcs(bucketForArchive, srtPath, srtText, 'application/x-subrip; charset=utf-8'),
            saveStringToGcs(bucketForArchive, vttPath, vttText, 'text/vtt; charset=utf-8'),
          ]);

          await channelDocRef(channel).set(
            {
              transcription: {
                archivedToGcs: true,
                gcs: {
                  bucket: bucketForArchive,
                  basePrefix: base,
                  json: `gs://${bucketForArchive}/${jsonPath}`,
                  txt: `gs://${bucketForArchive}/${txtPath}`,
                  srt: `gs://${bucketForArchive}/${srtPath}`,
                  vtt: `gs://${bucketForArchive}/${vttPath}`,
                },
              },
            },
            { merge: true }
          );
        } catch (archiveErr) {
          console.warn('⚠️ transcript archive to GCS failed:', archiveErr);
        }
      }

      return res.json({ ok: true });
    }

    if (status === 'error') {
      await channelDocRef(channel).set(
        { transcription: { ...baseUpdate, error: payload.error ?? 'unknown', completedAt: Date.now() } },
        { merge: true }
      );
      return res.json({ ok: true });
    }

    // Other statuses ("queued", "processing", etc.)
    await channelDocRef(channel).set({ transcription: baseUpdate }, { merge: true });
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ AssemblyAI webhook error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
};

// ========= Signed URLs for transcript artifacts =========
callsRouter.get('/:channelName/transcripts/urls', async (req, res) => {
  try {
    const { channelName } = req.params;
    const snap = await channelDocRef(channelName).get();
    const tr = snap.data()?.transcription;

    if (!tr?.archivedToGcs || !tr?.gcs?.bucket || !tr?.gcs?.basePrefix) {
      return res.status(404).json({ error: 'No archived transcript in GCS for this channel' });
    }

    const bucketName = tr.gcs.bucket as string;
    const base: string = tr.gcs.basePrefix as string;
    const path = (p: string) => `${base.replace(/\/$/, '')}/${p}`;

    const bucket = storage.bucket(bucketName);
    const mkFile = (obj: string) => bucket.file(obj);

    const trySign = async (obj: string) => {
      const f = mkFile(obj);
      const [exists] = await f.exists();
      if (!exists) return null;
      return signedReadUrl(f);
    };

    const [jsonUrl, txtUrl, srtUrl, vttUrl] = await Promise.all([
      trySign(path('transcript.json')),
      trySign(path('transcript.txt')),
      trySign(path('transcript.srt')),
      trySign(path('transcript.vtt')),
    ]);

    return res.json({
      bucket: bucketName,
      basePrefix: base,
      urls: { json: jsonUrl, txt: txtUrl, srt: srtUrl, vtt: vttUrl },
      expiresIn: GCS_SIGN_URL_TTL_SECONDS,
    });
  } catch (e) {
    console.error('❌ transcript urls error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});
