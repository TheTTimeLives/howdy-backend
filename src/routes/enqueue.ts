import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import { matchUsers } from '../services/matchmaker';
import { getGoLiveLockStatus } from '../services/behaviorInfractions';
import { logAuditEvent } from '../utils/audit';

export const enqueueRouter = express.Router();
enqueueRouter.use(verifyJwt);

enqueueRouter.get('/status', async (req, res) => {
  const uid = (req as any).uid;
  try {
    const lock = await getGoLiveLockStatus(uid);
    if (lock.isLocked) {
      return res.status(200).json({
        canGoLive: false,
        lockUntil: lock.lockUntil,
        notice: lock.notice,
      });
    }
    return res.status(200).json({ canGoLive: true });
  } catch (e) {
    console.error('Failed to get go-live status:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

enqueueRouter.post('/', async (req, res) => {
  const uid = (req as any).uid;
  const { prefs, scheduled, scheduledWindowEnd } = req.body;

  if (!prefs || typeof prefs !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid prefs object' });
  }

  try {
    const lock = await getGoLiveLockStatus(uid);
    if (lock.isLocked) {
      logAuditEvent({
        actorUid: uid,
        actorType: 'user',
        action: 'moderation_flagged',
        entityType: 'enqueue',
        entityId: uid,
        metadata: { reason: 'enqueue_lock_active', lockUntil: lock.lockUntil },
        category: 'moderation',
      }).catch(() => {});

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

    const isScheduled = scheduled === true && typeof scheduledWindowEnd === 'number';
    const queueData: Record<string, unknown> = {
      prefs,
      topic: prefs.topic || null,
      timestamp: Date.now(),
      state: 'searching',
    };
    if (isScheduled) {
      queueData.scheduled = true;
      queueData.scheduledWindowEnd = scheduledWindowEnd;
    }

    await db.collection('matchQueue').doc(uid).set(queueData);

    console.log(`📥 [ENQUEUE] uid=${uid} added to matchQueue (searching)${isScheduled ? ' [scheduled]' : ''}`);

    await matchUsers(); // ✅ now runs matchmaking after enqueue

    return res.status(200).json({ status: 'queued' });
  } catch (error) {
    console.error('Failed to enqueue user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
