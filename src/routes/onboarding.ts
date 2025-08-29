// src/routes/onboarding.ts
import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

type Stage = 'bio' | 'interests' | 'profile' | 'complete';

const STAGE_ORDER: Record<Stage, number> = {
  bio: 0,
  interests: 1,
  profile: 2,
  complete: 3,
};

const normalizeStage = (s: any): Stage =>
  s === 'interests' || s === 'profile' || s === 'complete' ? s : 'bio';

const canAdvanceTo = (current: Stage, target: Stage): boolean => {
  if (target === 'complete' && current !== 'profile') return false;
  return STAGE_ORDER[target] >= STAGE_ORDER[current];
};

export const onboardingRouter = express.Router();
onboardingRouter.use(verifyJwt);

// ---------- small retry helpers ----------
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const isTransient = (e: any) => {
  const code = e?.code ?? e?.status;
  const name = String(code).toUpperCase();
  return (
    code === 14 || // UNAVAILABLE
    code === 13 || // INTERNAL
    name.includes('UNAVAILABLE') ||
    name.includes('DEADLINE') ||
    name.includes('ABORT') ||
    name.includes('INTERNAL')
  );
};
async function withRetry<T>(fn: () => Promise<T>, max = 4): Promise<T> {
  let delay = 200;
  for (let i = 0; i < max; i++) {
    try { return await fn(); }
    catch (e) {
      if (!isTransient(e) || i === max - 1) throw e;
      await sleep(delay + Math.floor(Math.random() * 150));
      delay = Math.min(delay * 2, 2000);
    }
  }
  throw new Error('retry exhausted');
}

// ---------- GET /onboarding/hobbies ----------
type Hobby = { id: number; name: string; children?: Hobby[] };
let hobbiesCache: { items: Hobby[]; fetchedAt: number } | null = null;
const HOBBIES_TTL_MS = 5 * 60 * 1000;

onboardingRouter.get('/hobbies', async (req, res) => {
  try {
    const uid: string =
      (req as any).user?.uid || (req as any).userId || (req as any).uid;
    if (!uid) return res.status(401).json({ error: 'Unauthorized' });

    const now = Date.now();
    if (!hobbiesCache || now - hobbiesCache.fetchedAt > HOBBIES_TTL_MS) {
      const snap = await withRetry(() =>
        db.collection('hobbies').orderBy('id').get()
      );
      hobbiesCache = {
        items: snap.docs.map((d) => d.data() as Hobby),
        fetchedAt: now,
      };
    }

    const meta = await withRetry(() =>
      db.collection('user_metadata').doc(uid).get()
    );
    const selectedRaw = meta.data()?.backgroundBio?.interests ?? [];
    const selected: number[] = (Array.isArray(selectedRaw) ? selectedRaw : [])
      .map((x) => (typeof x === 'number' ? x : parseInt(String(x), 10)))
      .filter((n) => Number.isFinite(n));

    return res.json({ hobbies: hobbiesCache.items, selected });
  } catch (e) {
    console.error('❌ GET /onboarding/hobbies failed', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// ---------- POST /onboarding ----------
// All onboarding writes go to user_metadata/{uid}, including onboardingStage.
onboardingRouter.post('/', async (req, res) => {
  try {
    const uid: string =
      (req as any).user?.uid || (req as any).userId || (req as any).uid;
    if (!uid) return res.status(401).json({ error: 'Unauthorized' });

    const { bioResponses, interests, username, photoUrl, advanceTo } =
      (req.body ?? {}) as {
        bioResponses?: Record<string, unknown>;
        interests?: unknown[];
        username?: unknown;
        photoUrl?: unknown;
        advanceTo?: Stage;
      };

    // Build updates for user_metadata
    const metaUpdates: Record<string, any> = {};

    if (bioResponses && typeof bioResponses === 'object') {
      const cleaned: Record<string, string> = {};
      for (const [k, v] of Object.entries(bioResponses)) {
        if (typeof v === 'string') cleaned[k] = v.trim();
      }
      metaUpdates['bioResponses'] = cleaned;
    }

    if (Array.isArray(interests)) {
      const list = interests
        .map((x) => (typeof x === 'number' ? x : parseInt(String(x), 10)))
        .filter((n) => Number.isFinite(n));
      metaUpdates['backgroundBio.interests'] = Array.from(new Set(list));
    }

    if (typeof username === 'string' && username.trim()) {
      metaUpdates['username'] = username.trim();
    }
    if (typeof photoUrl === 'string' && photoUrl.trim()) {
      metaUpdates['photoUrl'] = photoUrl.trim();
    }

    const userRef = db.collection('users').doc(uid);
    const metaRef = db.collection('user_metadata').doc(uid);

    const result = await db.runTransaction(async (tx) => {
      const [userSnap, metaSnap] = await Promise.all([tx.get(userRef), tx.get(metaRef)]);

      // Read current stage from user_metadata first; fall back to users (legacy); default 'bio'
      const metaStage = metaSnap.exists ? metaSnap.get('onboardingStage') : undefined;
      const userStageLegacy = userSnap.exists ? userSnap.get('onboardingStage') : undefined;
      const current: Stage = normalizeStage(metaStage ?? userStageLegacy);

      // Apply non-stage updates to user_metadata
      if (Object.keys(metaUpdates).length > 0) {
        tx.set(metaRef, metaUpdates, { merge: true });
      }

      // Stage progression (also written to user_metadata)
      let newStage = current;
      if (advanceTo && typeof advanceTo === 'string') {
        const target = normalizeStage(advanceTo);
        if (canAdvanceTo(current, target)) {
          newStage = target;
        }
      }
      // Always ensure onboardingStage exists in user_metadata (even if unchanged)
      tx.set(metaRef, { onboardingStage: newStage }, { merge: true });

      // (Optional legacy cleanup: you could clear users/{uid}.onboardingStage here if desired)
      // tx.set(userRef, { onboardingStage: admin.firestore.FieldValue.delete() }, { merge: true });

      return { stage: newStage };
    });

    return res.json({ ok: true, stage: result.stage });
  } catch (e) {
    console.error('❌ POST /onboarding error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});
