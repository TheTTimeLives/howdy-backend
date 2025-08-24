import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const subscriptionsRouter = express.Router();
subscriptionsRouter.use(verifyJwt);

// GET /subscriptions/groups/:groupId/status
subscriptionsRouter.get('/groups/:groupId/status', async (req, res) => {
  const { groupId } = req.params;
  try {
    const doc = await db.collection('groups').doc(groupId).get();
    if (!doc.exists) return res.status(404).json({ error: 'Group not found' });
    const data = doc.data() || {};
    return res.status(200).json({
      tier: data.tier || 'trial',
      trialEndsAt: data.trialEndsAt || null,
      active: data.subscriptionActive === true,
    });
  } catch (e) {
    console.error('❌ subscription status failed', e);
    return res.status(500).json({ error: 'Failed to load subscription status' });
  }
});

// POST /subscriptions/groups/:groupId/start-trial
subscriptionsRouter.post('/groups/:groupId/start-trial', async (req, res) => {
  const { groupId } = req.params;
  try {
    const ref = db.collection('groups').doc(groupId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Group not found' });
    const data = snap.data() || {};
    if (data.trialEndsAt && Date.now() < data.trialEndsAt) {
      return res.status(200).json({ ok: true, trialEndsAt: data.trialEndsAt });
    }
    const trialEndsAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await ref.set({ tier: 'trial', trialEndsAt }, { merge: true });
    return res.status(200).json({ ok: true, trialEndsAt });
  } catch (e) {
    console.error('❌ start trial failed', e);
    return res.status(500).json({ error: 'Failed to start trial' });
  }
});

// POST /subscriptions/groups/:groupId/plan { tier }
subscriptionsRouter.post('/groups/:groupId/plan', async (req, res) => {
  const { groupId } = req.params;
  const tier = String(req.body?.tier || '').toLowerCase();
  const allowed = ['basic', 'standard', 'pro'];
  if (!allowed.includes(tier)) {
    return res.status(400).json({ error: 'Invalid tier' });
  }
  try {
    await db.collection('groups').doc(groupId).set({
      tier,
      subscriptionActive: true,
    }, { merge: true });
    return res.status(200).json({ ok: true, tier, active: true });
  } catch (e) {
    console.error('❌ set plan failed', e);
    return res.status(500).json({ error: 'Failed to set plan' });
  }
});


