import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const usersRouter = express.Router();
usersRouter.use(verifyJwt);

usersRouter.get('/me', async (req, res) => {
  const uid = (req as any).uid;

  try {
    const metadataDoc = await db.collection('user_metadata').doc(uid).get();
    if (!metadataDoc.exists) return res.status(404).json({ error: 'User metadata not found' });

    return res.status(200).json(metadataDoc.data());
  } catch (e) {
    console.error('❌ Fetch error:', e);
    return res.status(500).json({ error: 'Failed to fetch user metadata' });
  }
});

usersRouter.post('/verification/reset', async (req, res) => {
  const uid = (req as any).uid;
  try {
    await db.collection('user_metadata').doc(uid).update({
      verificationStatus: 'awaiting',
    });
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to reset verification status' });
  }
});

