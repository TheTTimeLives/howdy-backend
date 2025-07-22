import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const pushRouter = express.Router();
pushRouter.use(verifyJwt);

pushRouter.post('/register', async (req, res) => {
  const uid = (req as any).uid;
  const { token } = req.body;

  if (!token) return res.status(400).json({ error: 'Missing token' });

  try {
    await db
      .collection('users')
      .doc(uid)
      .collection('pushTokens')
      .doc(token)
      .set({
        token,
        createdAt: Date.now(),
      });

    return res.status(200).json({ status: 'registered' });
  } catch (err) {
    console.error('🔥 Failed to register push token:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

pushRouter.delete('/token', async (req, res) => {
  const uid = (req as any).uid;
  const { token } = req.body;

  if (!token) return res.status(400).json({ error: 'Missing token' });

  try {
    await db.collection('users').doc(uid).collection('pushTokens').doc(token).delete();
    return res.status(200).json({ status: 'deleted' });
  } catch (err) {
    console.error('Failed to delete token:', err);
    return res.status(500).json({ error: 'Failed to remove token' });
  }
});