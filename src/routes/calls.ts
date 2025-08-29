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
    : RtcRole.PUBLISHER; // default PUBLISHER (more permissive in many apps)

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
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ /calls/start error', e);
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

    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ /calls/:channelName/end error', e);
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
    if (parts.length >= 2) {
      const sorted = parts.slice(0, 2).sort();
      [a, b] = sorted;
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

// ========= Start lock (race-proof) =========
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

// START recording (server endpoint called after users joined; call exactly once)
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

      // success
      return res.json({ ok: true, resourceId, sid });
    } catch (err) {
      // optional: write an error marker to the doc
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

// STOP recording (client calls on hangup; should be called once)
callsRouter.post('/:channelName/record/stop', async (req, res) => {
  try {
    const { channelName } = req.params;

    const snap = await channelDocRef(channelName).get();
    const rec = snap.data()?.rec;

    if (!rec?.resourceId || !rec?.sid) {
      return res.status(400).json({ error: 'No active recording for this channel' });
    }

    // If already stopped, make it idempotent
    if (rec?.stoppedAt) {
      return res.json({ ok: true, alreadyStopped: true });
    }

    // MUST use the SAME numeric uid as /start (our dedicated recorder UID)
    const recorderUid: string = String(rec.recorderUid || RECORDER_UID);
    if (!/^\d+$/.test(recorderUid)) {
      return res.status(500).json({ error: 'Invalid recorderUid stored for this call' });
    }

    await stopRecording(rec.resourceId, rec.sid, channelName, recorderUid);

    await channelDocRef(channelName).set({ rec: { ...rec, stoppedAt: Date.now() } }, { merge: true });

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
const AUDIO_EXT_RE = /\.(m4a|aac|wav|mp3|mp4|m3u8|ts)$/i;

async function listLatestFileUnderPrefix(bucketName: string, prefixesToTry: string[]): Promise<File | null> {
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
    return withMeta[0].f;
  }

  return null;
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

    const file = await listLatestFileUnderPrefix(rec.bucket, prefixes);
    if (!file) return res.status(404).json({ error: 'No recording files found yet' });

    const url = await signedReadUrl(file);
    return res.json({ bucket: rec.bucket, object: file.name, url, expiresIn: GCS_SIGN_URL_TTL_SECONDS });
  } catch (e) {
    console.error('❌ signed url error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// ========= AssemblyAI submission =========
callsRouter.post('/:channelName/transcribe', async (req, res) => {
  try {
    if (!ASSEMBLYAI_API_KEY) {
      return res.status(500).json({ error: 'Missing ASSEMBLYAI_API_KEY' });
    }

    const { channelName } = req.params;
    const callDoc = await channelDocRef(channelName).get();
    const rec = callDoc.data()?.rec;

    if (!rec?.bucket) {
      return res.status(400).json({ error: 'No recording info on call doc' });
    }

    const prefixes: string[] = [String(rec.objectPathBase || '')];
    const recomputed = await buildRecordingPrefix(channelName);
    if (recomputed.objectPathBase && recomputed.objectPathBase !== prefixes[0]) {
      prefixes.push(recomputed.objectPathBase);
    }

    const file = await listLatestFileUnderPrefix(rec.bucket, prefixes);
    if (!file) {
      return res.status(404).json({ error: 'Recording file not found (yet). Try again shortly.' });
    }

    const signedUrl = await signedReadUrl(file);

    const webhookUrlBase = process.env.API_BASE_URL || '';
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
      }),
    });

    if (!aaiResp.ok) {
      const t = await aaiResp.text();
      return res.status(502).json({ error: `AssemblyAI submit failed ${aaiResp.status}: ${t}` });
    }

    const data = await aaiResp.json();
    await channelDocRef(channelName).set(
      { transcription: { id: data.id, status: 'submitted', submittedAt: Date.now() } },
      { merge: true }
    );

    return res.json({ ok: true, id: data.id });
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

// ========= Webhook =========
export const assemblyAiWebhookHandler: RequestHandler = async (req, res) => {
  try {
    const sig = String(req.header('X-AI-Signature') || '');
    if (sig !== ASSEMBLYAI_WEBHOOK_SECRET) {
      return res.status(401).json({ error: 'Invalid webhook signature' });
    }

    const channel = String(req.query.channel || '');
    if (!channel) return res.status(400).json({ error: 'Missing channel' });

    const payload = req.body || {};
    const status = String(payload.status || '');

    if (status === 'completed') {
      await channelDocRef(channel).set(
        {
          transcription: {
            id: payload.id,
            status,
            text: payload.text ?? null,
            summary: payload.summary ?? null,
            completedAt: Date.now(),
          },
        },
        { merge: true }
      );

      if (ARCHIVE_TRANSCRIPTS_TO_GCS && GCS_BUCKET) {
        try {
          const [fullJson, plainText, srtText, vttText] = await Promise.all([
            fetchAaiJson(payload.id),
            fetchAaiText(payload.id),
            fetchAaiSrt(payload.id),
            fetchAaiVtt(payload.id),
          ]);

          const base = `${TRANSCRIPTS_PREFIX}/${encodeURIComponent(channel)}/${payload.id}`;
          const jsonPath = `${base}/transcript.json`;
          const txtPath = `${base}/transcript.txt`;
          const srtPath = `${base}/transcript.srt`;
          const vttPath = `${base}/transcript.vtt`;

          await Promise.all([
            saveStringToGcs(GCS_BUCKET, jsonPath, JSON.stringify(fullJson, null, 2), 'application/json'),
            saveStringToGcs(GCS_BUCKET, txtPath, plainText, 'text/plain; charset=utf-8'),
            saveStringToGcs(GCS_BUCKET, srtPath, srtText, 'application/x-subrip; charset=utf-8'),
            saveStringToGcs(GCS_BUCKET, vttPath, vttText, 'text/vtt; charset=utf-8'),
          ]);

          await channelDocRef(channel).set(
            {
              transcription: {
                archivedToGcs: true,
                gcs: {
                  bucket: GCS_BUCKET,
                  basePrefix: base,
                  json: `gs://${GCS_BUCKET}/${jsonPath}`,
                  txt: `gs://${GCS_BUCKET}/${txtPath}`,
                  srt: `gs://${GCS_BUCKET}/${srtPath}`,
                  vtt: `gs://${GCS_BUCKET}/${vttPath}`,
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
        { transcription: { id: payload.id, status, error: payload.error, completedAt: Date.now() } },
        { merge: true }
      );
      return res.json({ ok: true });
    }

    await channelDocRef(channel).set(
      { transcription: { id: payload.id, status, updatedAt: Date.now() } },
      { merge: true }
    );
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
