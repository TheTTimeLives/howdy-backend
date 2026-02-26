import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import { matchUsers } from '../services/matchmaker';
import { getGoLiveLockStatus } from '../services/behaviorInfractions';

export const enqueueRouter = express.Router();
enqueueRouter.use(verifyJwt);

enqueueRouter.post('/', async (req, res) => {
  const uid = (req as any).uid;
  const { prefs } = req.body;

  if (!prefs || typeof prefs !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid prefs object' });
  }

  try {
    const lock = await getGoLiveLockStatus(uid);
    if (lock.isLocked) {
      return res.status(423).json({
        error: 'GO_LIVE_LOCKED',
        lockUntil: lock.lockUntil,
        moderation: {
          notice: lock.notice,
          recommendedTakeOffline: true,
          recommendedLockUntil: lock.lockUntil,
          reason: 'enqueue_lock_active',
        },
      });
    }

    await db.collection('matchQueue').doc(uid).set({
      prefs,
      topic: prefs.topic || null, // ✅ Save optional topic
      timestamp: Date.now(),
      state: 'searching',
    });


    await matchUsers(); // ✅ now runs matchmaking after enqueue

    return res.status(200).json({ status: 'queued' });
  } catch (error) {
    console.error('Failed to enqueue user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
