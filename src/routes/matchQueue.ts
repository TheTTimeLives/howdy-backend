import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const matchQueueRouter = express.Router();
matchQueueRouter.use(verifyJwt);

matchQueueRouter.get('/:uid', async (req, res) => {
  const { uid } = req.params;
  const callerUid = (req as any).uid;

  try {
    const doc = await db.collection('matchQueue').doc(uid).get();
    if (!doc.exists) {
      if (uid === callerUid) {
        console.log(`📭 [MATCH_QUEUE] GET uid=${uid} → 404 (doc not found, caller=${callerUid})`);
      }
      return res.status(404).json({ error: 'Not in queue' });
    }

    // Heartbeat: update lastPolledAt when caller polls their own doc
    if (uid === callerUid) {
      doc.ref.update({ lastPolledAt: Date.now() }).catch(() => {});
    }

    return res.json(doc.data());
  } catch (error) {
    console.error('Failed to get match status:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

matchQueueRouter.delete('/:uid', async (req, res) => {
  const { uid } = req.params;

  try {
    await db.collection('matchQueue').doc(uid).delete();
    return res.status(200).json({ status: 'deleted' });
  } catch (err) {
    console.error('Failed to cleanup matchQueue:', err);
    return res.status(500).json({ error: 'Failed to remove user from queue' });
  }
});
