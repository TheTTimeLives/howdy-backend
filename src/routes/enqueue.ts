import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const enqueueRouter = express.Router();
enqueueRouter.use(verifyJwt);

enqueueRouter.post('/', async (req, res) => {
  const uid = (req as any).uid;
  const { prefs } = req.body;

  if (!prefs || typeof prefs !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid prefs object' });
  }

  try {
    await db.collection('matchQueue').doc(uid).set({
      prefs,
      timestamp: Date.now(),
      status: 'waiting',
    });

    return res.status(200).json({ status: 'queued' });
  } catch (error) {
    console.error('Failed to enqueue user:', error);
    return res.status(500).json({ error: 'Internal server error' });
  }
});
