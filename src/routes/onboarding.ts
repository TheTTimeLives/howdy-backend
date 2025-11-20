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
    const requesterUid: string =
      (req as any).user?.uid || (req as any).userId || (req as any).uid;
    if (!requesterUid) return res.status(401).json({ error: 'Unauthorized' });

    // Optional memberId to act on behalf of a member (carer/org/guardian)
    const memberId = typeof req.query.memberId === 'string' ? req.query.memberId : undefined;

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

    let targetUid = requesterUid;

    if (memberId && memberId !== requesterUid) {
      // authorize caregiver to read on behalf
      const [memberMetaSnap, requesterGroupsSnap] = await Promise.all([
        withRetry(() => db.collection('user_metadata').doc(memberId).get()),
        withRetry(() => db.collection('groups').get()),
      ]);

      if (!memberMetaSnap.exists) return res.status(404).json({ error: 'Member not found' });
      const mdata = memberMetaSnap.data() || {};
      if ((mdata.accountType || '') !== 'member') {
        return res.status(400).json({ error: 'Target user is not a member' });
      }
      const guardianUid = mdata.guardianUid as string | undefined;
      const primaryGroupId = mdata.primaryGroupId as string | undefined;

      let authorized = false;
      if (guardianUid && guardianUid === requesterUid) authorized = true;
      if (!authorized && primaryGroupId) {
        const mem = await withRetry(() =>
          db.collection('groups').doc(primaryGroupId).collection('members').doc(requesterUid).get()
        );
        const role = mem.data()?.role || 'member';
        if (['admin', 'super-admin'].includes(String(role))) authorized = true;
      }
      if (!authorized) return res.status(403).json({ error: 'Forbidden' });
      targetUid = memberId;
    }

    const meta = await withRetry(() =>
      db.collection('user_metadata').doc(targetUid).get()
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

// ---------- POST /onboarding/next-question ----------
// Generate a follow-up question using GPT; fallback to stored follow-ups if GPT is unavailable.
onboardingRouter.post('/next-question', async (req, res) => {
  try {
    const requesterUid: string =
      (req as any).user?.uid || (req as any).userId || (req as any).uid;
    if (!requesterUid) return res.status(401).json({ error: 'Unauthorized' });

    const { memberId, seedQuestion, previousAnswers, forcePivot, rejectedQuestion } = (req.body ?? {}) as {
      memberId?: string;
      seedQuestion?: string;
      previousAnswers?: Array<{ question: string; answer: string }>;
      forcePivot?: boolean;
      rejectedQuestion?: string;
    };

    // Determine target for read authorization (if memberId provided)
    let targetUid = requesterUid;
    if (memberId && memberId !== requesterUid) {
      const memberRef = db.collection('user_metadata').doc(memberId);
      const memberSnap = await withRetry(() => memberRef.get());
      if (!memberSnap.exists) return res.status(404).json({ error: 'Member not found' });
      const mdata = memberSnap.data() || {};
      if ((mdata.accountType || '') !== 'member') {
        return res.status(400).json({ error: 'Target user is not a member' });
      }
      const guardianUid = mdata.guardianUid as string | undefined;
      const primaryGroupId = mdata.primaryGroupId as string | undefined;
      let authorized = false;
      if (guardianUid && guardianUid === requesterUid) authorized = true;
      if (!authorized && primaryGroupId) {
        const mem = await withRetry(() =>
          db.collection('groups').doc(primaryGroupId).collection('members').doc(requesterUid).get()
        );
        const role = mem.data()?.role || 'member';
        if (['admin', 'super-admin'].includes(String(role))) authorized = true;
      }
      if (!authorized) return res.status(403).json({ error: 'Forbidden' });
      targetUid = memberId;
    }

    const key = process.env.OPENAI_API_KEY;

  // Enforce a hard cap server-side as well
  if (Array.isArray(previousAnswers) && previousAnswers.length >= 12) {
    return res.json({ question: '', limit: true });
  }

  const buildPrompt = (): { messages: any[] } => {
    const intro =
      "You are Howdy's friendly icebreaker assistant. Ask exactly ONE short, engaging follow-up question. " +
      'Keep it safe for all audiences, avoid PII, and be supportive. Output only the question.';
    const threading =
      'The first user answer lists two or more hobbies and interests. Choose one topic to focus on and ask up to 3 follow-up questions about that topic before pivoting to another. ' +
      'Use the conversation history to infer which topic you have been on and how many follow-ups have been asked for that topic. ' +
      'After 3 follow-ups on a topic, pivot to a different one until each has had up to 3. ' +
      'If all topics have reached 3 follow-ups, ask if they want to share more interests or revisit an earlier one with a fresh angle. ' +
      'Ask only a single concise question; do not include explanations or lists.';
    const singleSubjectRule =
      'Important: Each follow-up must focus on EXACTLY ONE of the user’s hobbies/interests. ' +
      'Do NOT combine multiple subjects in a single question (avoid “and/or” constructions). ' +
      'Select one subject and ask about only that subject.';

    const msgs: any[] = [
      { role: 'system', content: intro },
      { role: 'system', content: threading },
      { role: 'system', content: singleSubjectRule },
    ];

    if (seedQuestion) {
      msgs.push({ role: 'user', content: `Seed question: ${seedQuestion}` });
    }

    if (Array.isArray(previousAnswers) && previousAnswers.length > 0) {
      const historyLines = previousAnswers
        .map((p, i) => `Q${i + 1}: ${p.question}\nA${i + 1}: ${p.answer}`)
        .join('\n');
      msgs.push({
        role: 'user',
        content: `Conversation so far:\n${historyLines}\n\nAsk one next follow-up per the rules.`,
      });
    } else {
      msgs.push({ role: 'user', content: 'Ask a friendly icebreaker.' });
    }

    if (forcePivot === true) {
      msgs.push({
        role: 'system',
        content:
          'Pivot to a different subject than the one most recently discussed. Choose another topic from the user’s earlier list of interests and ask one concise follow-up about it. Do not continue the current topic.',
      });
      if (typeof rejectedQuestion === 'string' && rejectedQuestion.trim()) {
        msgs.push({
          role: 'user',
          content:
            `The last follow-up question you generated was rejected: "${rejectedQuestion}". ` +
            'Generate a different follow-up that addresses the original intent without asking about any subjects/keywords mentioned in that rejected question. For example, if the rejected question was about "travel", do not ask about "travel" again.' +
            'If in follow that instruction and there are no subjects remaining to ask about, ask how they got started in their hobbies.',
        });
        // Include the initial hobbies/interests answer for context so GPT can select a different subject
        const initialAnswer =
          Array.isArray(previousAnswers) && previousAnswers.length > 0
            ? String(previousAnswers[0]?.answer ?? '').trim()
            : '';
        if (initialAnswer) {
          msgs.push({
            role: 'user',
            content:
              `Initial hobbies/interests answer: "${initialAnswer}". ` +
              'Choose a different subject from this list that was NOT mentioned in the rejected question. If none remain, ask how they got started in their hobbies.',
          });
        }
      }
      console.log('Sent pivoted prompt to GPT:', msgs);
    }
    console.log('Sent prompt to GPT:', msgs);
    return { messages: msgs };
  };

    // Try GPT first
    if (key) {
      try {
        const payload = {
          model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
          temperature: 0.7,
          max_tokens: 80,
          ...buildPrompt(),
        };
        const f = (globalThis as any).fetch as typeof fetch | undefined;
        if (!f) throw new Error('fetch unavailable');
        const r = await f('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${key}`,
            'Content-Type': 'application/json',
            ...(process.env.OPENAI_ORG ? { 'OpenAI-Organization': process.env.OPENAI_ORG as string } : {}),
            ...(process.env.OPENAI_PROJECT ? { 'OpenAI-Project': process.env.OPENAI_PROJECT as string } : {}),
          },
          body: JSON.stringify(payload),
        });
        if (r.ok) {
          const data = await r.json();
          const content = data?.choices?.[0]?.message?.content?.toString()?.trim();
          if (content && content.length > 0) {
            return res.json({ question: content, source: 'gpt' });
          }
        } else {
          console.warn('⚠️ OpenAI API error', await r.text());
        }
      } catch (e) {
        console.warn('⚠️ OpenAI request failed; falling back', e);
      }
    }

    // Fallback to stored follow-ups (simple heuristic)
    // Try collection 'onboarding_followups' with doc id == seedQuestion (sanitized), else generic 'icebreakers'
    let fbQuestion: string | null = null;
    try {
      const docId = (seedQuestion || 'icebreakers').toString().toLowerCase().slice(0, 120);
      const fbRef = db.collection('onboarding_followups').doc(docId);
      const snap = await fbRef.get();
      if (snap.exists) {
        const arr = (snap.get('questions') as string[] | undefined) || [];
        if (arr.length > 0) {
          // choose next by number of previous answers, else first
          const idx = Math.min(
            Array.isArray(previousAnswers) ? previousAnswers.length : 0,
            Math.max(0, arr.length - 1)
          );
          fbQuestion = String(arr[idx] || arr[0]);
        }
      }
    } catch (_) {}

    if (!fbQuestion) {
      // Final fallback: pick next “onboarding_questions” by order (generic)
      try {
        const qs = await db
          .collection('onboarding_questions')
          .where('active', '==', true)
          .orderBy('order')
          .limit(5)
          .get();
        if (!qs.empty) {
          fbQuestion = String(qs.docs[Math.min(1, qs.docs.length - 1)].data().text || 'Tell me more about that.');
        }
      } catch (_) {
        fbQuestion = 'Tell me more about that.';
      }
    }

    return res.json({ question: fbQuestion, source: 'fallback' });
  } catch (e) {
    console.error('❌ POST /onboarding/next-question error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});

// ---------- POST /onboarding ----------
// All onboarding writes go to user_metadata/{uid}, including onboardingStage.
onboardingRouter.post('/', async (req, res) => {
  try {
    const requesterUid: string =
      (req as any).user?.uid || (req as any).userId || (req as any).uid;
    if (!requesterUid) return res.status(401).json({ error: 'Unauthorized' });

    const { bioResponses, interests, username, photoUrl, advanceTo, memberId, clearBio } =
      (req.body ?? {}) as {
        bioResponses?: Record<string, unknown>;
        interests?: unknown[];
        username?: unknown;
        photoUrl?: unknown;
        advanceTo?: Stage;
        memberId?: string;
        clearBio?: boolean;
      };

    // Debug log: request summary (no PII)
    try {
      console.log('[ONBOARDING POST] requester=%s target=%s advanceTo=%s',
        requesterUid, String(memberId || requesterUid), String(advanceTo || ''));
    } catch (_e) {}

    // Determine target user to write to (self or managed member)
    let targetUid = requesterUid;
    if (memberId && memberId !== requesterUid) {
      const memberRef = db.collection('user_metadata').doc(memberId);
      const memberSnap = await withRetry(() => memberRef.get());
      if (!memberSnap.exists) return res.status(404).json({ error: 'Member not found' });
      const mdata = memberSnap.data() || {};
      if ((mdata.accountType || '') !== 'member') {
        return res.status(400).json({ error: 'Target user is not a member' });
      }
      const guardianUid = mdata.guardianUid as string | undefined;
      const primaryGroupId = mdata.primaryGroupId as string | undefined;
      let authorized = false;
      if (guardianUid && guardianUid === requesterUid) authorized = true;
      if (!authorized && primaryGroupId) {
        const mem = await withRetry(() =>
          db.collection('groups').doc(primaryGroupId).collection('members').doc(requesterUid).get()
        );
        const role = mem.data()?.role || 'member';
        if (['admin', 'super-admin'].includes(String(role))) authorized = true;
      }
      if (!authorized) return res.status(403).json({ error: 'Forbidden' });
      targetUid = memberId;
    }

    // Build updates for user_metadata
    const metaUpdates: Record<string, any> = {};

    if (clearBio === true) {
      metaUpdates['bioResponses'] = {};
    } else if (bioResponses && typeof bioResponses === 'object') {
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

    const userRef = db.collection('users').doc(targetUid);
    const metaRef = db.collection('user_metadata').doc(targetUid);

    const result = await db.runTransaction(async (tx) => {
      const [userSnap, metaSnap] = await Promise.all([tx.get(userRef), tx.get(metaRef)]);

      // Read current stage from user_metadata first; fall back to users (legacy); default 'bio'
      const metaStage = metaSnap.exists ? metaSnap.get('onboardingStage') : undefined;
      const userStageLegacy = userSnap.exists ? userSnap.get('onboardingStage') : undefined;
      const current: Stage = normalizeStage(metaStage ?? userStageLegacy);
      const acct = metaSnap.exists ? (metaSnap.get('accountType') as string | undefined) : undefined;

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

      // Debug inside txn for determinism
      try {
        console.log('[ONBOARDING TX] uid=%s acct=%s current=%s targetAdvance=%s new=%s',
          targetUid,
          acct ?? 'unknown',
          current,
          String(advanceTo || ''),
          newStage
        );
      } catch (_e) {}

      return { stage: newStage };
    });

    return res.json({ ok: true, stage: result.stage });
  } catch (e) {
    console.error('❌ POST /onboarding error', e);
    return res.status(500).json({ error: 'Internal Error' });
  }
});
