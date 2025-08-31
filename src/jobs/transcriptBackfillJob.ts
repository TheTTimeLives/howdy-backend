// src/jobs/transcriptBackfillJob.ts
import fetch from 'node-fetch';
import { Storage } from '@google-cloud/storage';
import { db } from '../firebase';

const storage = new Storage();

const ASSEMBLYAI_API_KEY = process.env.ASSEMBLYAI_API_KEY || '';
const ARCHIVE_TRANSCRIPTS_TO_GCS =
  String(process.env.ARCHIVE_TRANSCRIPTS_TO_GCS || 'false').toLowerCase() === 'true';
const GCS_BUCKET_DEFAULT = process.env.GCS_BUCKET || '';
const TRANSCRIPTS_PREFIX = process.env.TRANSCRIPTS_PREFIX || 'transcripts';

/** Helpers to fetch artifacts from AAI */
async function aaiGetJson(id: string): Promise<any> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${id}`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY },
  });
  if (!r.ok) throw new Error(`AAI JSON ${id} failed ${r.status}: ${await r.text()}`);
  return r.json();
}
async function aaiGetText(id: string): Promise<string> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${id}`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY, Accept: 'text/plain' },
  });
  if (!r.ok) throw new Error(`AAI TXT ${id} failed ${r.status}: ${await r.text()}`);
  return r.text();
}
async function aaiGetSrt(id: string): Promise<string> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${id}/srt`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY },
  });
  if (!r.ok) throw new Error(`AAI SRT ${id} failed ${r.status}: ${await r.text()}`);
  return r.text();
}
async function aaiGetVtt(id: string): Promise<string> {
  const r = await fetch(`https://api.assemblyai.com/v2/transcript/${id}/vtt`, {
    headers: { Authorization: ASSEMBLYAI_API_KEY },
  });
  if (!r.ok) throw new Error(`AAI VTT ${id} failed ${r.status}: ${await r.text()}`);
  return r.text();
}

async function saveStringToGcs(
  bucketName: string,
  objectName: string,
  contents: string,
  contentType = 'text/plain; charset=utf-8'
) {
  const file = storage.bucket(bucketName).file(objectName);
  await file.save(contents, { resumable: false, contentType, public: false });
}

/**
 * Equivalent to the "finalizeTranscriptAndArchive" logic:
 * - Updates Firestore status
 * - Writes JSON/TXT/SRT/VTT under calls/<…>/transcripts/<id>/
 * - Sets transcription.gcs to the correct per‑call base
 */
async function finalizeTranscriptAndArchive(
  channelName: string,
  transcriptId: string,
  payloadFromAAI?: any
) {
  // Load call to discover rec bucket + base prefix
  const snap = await db.collection('calls').doc(`chan_${channelName}`).get();
  const call = snap.data() || {};
  const rec = call.rec || {};

  const bucket = String(rec.bucket || GCS_BUCKET_DEFAULT || '');
  if (!bucket) {
    // We still mark completed in Firestore, even if we can't archive
    await snap.ref.set(
      {
        transcription: {
          id: transcriptId,
          status: 'completed',
          text: payloadFromAAI?.text ?? null,
          summary: payloadFromAAI?.summary ?? null,
          completedAt: Date.now(),
        },
      },
      { merge: true }
    );
    return;
  }

  // Prefer saving *next to the call recording*
  const recBase: string | undefined =
    typeof rec.objectPathBase === 'string' ? rec.objectPathBase : undefined;

  const base = recBase
    ? `${recBase.replace(/\/$/, '')}/transcripts/${transcriptId}`
    : `${TRANSCRIPTS_PREFIX}/${encodeURIComponent(channelName)}/${transcriptId}`;

  const jsonPath = `${base}/transcript.json`;
  const txtPath = `${base}/transcript.txt`;
  const srtPath = `${base}/transcript.srt`;
  const vttPath = `${base}/transcript.vtt`;

  // Pull artifacts (reuse payload if we already fetched JSON)
  const [fullJson, plainText, srtText, vttText] = await Promise.all([
    payloadFromAAI ?? aaiGetJson(transcriptId),
    aaiGetText(transcriptId),
    aaiGetSrt(transcriptId),
    aaiGetVtt(transcriptId),
  ]);

  if (ARCHIVE_TRANSCRIPTS_TO_GCS) {
    await Promise.all([
      saveStringToGcs(bucket, jsonPath, JSON.stringify(fullJson, null, 2), 'application/json'),
      saveStringToGcs(bucket, txtPath, plainText, 'text/plain; charset=utf-8'),
      saveStringToGcs(bucket, srtPath, srtText, 'application/x-subrip; charset=utf-8'),
      saveStringToGcs(bucket, vttPath, vttText, 'text/vtt; charset=utf-8'),
    ]);
  }

  await snap.ref.set(
    {
      transcription: {
        id: transcriptId,
        status: 'completed',
        text: fullJson?.text ?? null,
        summary: fullJson?.summary ?? null,
        archivedToGcs: !!ARCHIVE_TRANSCRIPTS_TO_GCS,
        gcs: ARCHIVE_TRANSCRIPTS_TO_GCS
          ? {
              bucket,
              basePrefix: base,
              json: `gs://${bucket}/${jsonPath}`,
              txt: `gs://${bucket}/${txtPath}`,
              srt: `gs://${bucket}/${srtPath}`,
              vtt: `gs://${bucket}/${vttPath}`,
            }
          : undefined,
        completedAt: Date.now(),
      },
    },
    { merge: true }
  );
}

/**
 * Daily job: (1) submit any calls that never got submitted; (2) poll and finalize
 * any calls stuck in submitted/queued/processing; (3) archive completed-but-not-archived.
 */
export async function runTranscriptBackfillJob() {
  const cutoff = Date.now() - 1000 * 60 * 5; // ignore very recent calls (<5m)
  const baseUrl = process.env.API_BASE_URL || ''; // used to POST /calls/:channel/transcribe
  const cronToken = process.env.CRON_SERVICE_TOKEN || '';

  // Pull all calls that have recordings (we'll filter in code)
  const snap = await db.collection('calls').where('rec.bucket', '!=', null).get();

  let submitted = 0;
  let polled = 0;
  let finalized = 0;
  let archivedOnly = 0;
  let errors = 0;

  for (const doc of snap.docs) {
    try {
      const data: any = doc.data() || {};
      const channelName = data.channelName as string | undefined;
      if (!channelName) continue;

      const rec = data.rec || {};
      if (!rec.bucket || !rec.objectPathBase) continue;

      const tr = data.transcription || {};
      const status: string | undefined = tr.status;
      const endedAt: number | undefined = data.endedAt;

      // (A) Already have an AAI id?
      if (tr.id) {
        const id = String(tr.id);

        // If webhook missed archiving but status shows completed -> archive now
        if (status === 'completed' && !tr.archivedToGcs) {
          try {
            const info = await aaiGetJson(id);
            await finalizeTranscriptAndArchive(channelName, id, info);
            archivedOnly++;
          } catch (e) {
            errors++;
            console.warn('⚠️ Backfill archive-only failed', channelName, id, e);
          }
          continue;
        }

        // If still in progress -> poll once and finalize if done
        if (status === 'submitted' || status === 'processing' || status === 'queued') {
          try {
            const info = await aaiGetJson(id);
            polled++;

            if (String(info.status) === 'completed') {
              await finalizeTranscriptAndArchive(channelName, id, info);
              finalized++;
            } else if (String(info.status) === 'error') {
              await doc.ref.set(
                { transcription: { id, status: 'error', error: info.error ?? 'unknown', updatedAt: Date.now() } },
                { merge: true }
              );
            } else {
              // keep status fresh in Firestore for visibility
              await doc.ref.set(
                { transcription: { id, status: String(info.status || ''), updatedAt: Date.now() } },
                { merge: true }
              );
            }
          } catch (e) {
            errors++;
            console.warn('⚠️ Backfill poll failed', channelName, id, e);
          }
          continue;
        }

        // Completed and archived -> nothing to do
        if (status === 'completed' && tr.archivedToGcs) {
          continue;
        }

        // Error state -> nothing automatic
        if (status === 'error') {
          continue;
        }
      }

      // (B) No transcript submitted yet? Try to submit if call ended a while ago.
      if (endedAt && endedAt <= cutoff && baseUrl) {
        try {
          const url = `${baseUrl}/calls/${encodeURIComponent(channelName)}/transcribe`;
          const headers: any = { 'Content-Type': 'application/json' };
          if (cronToken) headers.Authorization = `Bearer ${cronToken}`;

          const resp = await fetch(url, { method: 'POST', headers, body: '{}' });
          if (resp.ok) {
            submitted++;
            // mark that we attempted, even if webhook/poll finishes later
            await doc.ref.set(
              { transcription: { status: 'submitted', submittedAt: Date.now() } },
              { merge: true }
            );
          } else {
            const t = await resp.text();
            errors++;
            console.warn('⚠️ Backfill submit failed', channelName, resp.status, t);
          }
        } catch (e) {
          errors++;
          console.warn('⚠️ Backfill submit error', channelName, e);
        }
      }
    } catch (e) {
      errors++;
      console.warn('⚠️ Backfill error on doc', doc.id, e);
    }
  }

  console.log(
    `🗒️ Backfill: submitted=${submitted}, polled=${polled}, finalized=${finalized}, archivedOnly=${archivedOnly}, errors=${errors}`
  );
}
