import express from 'express';
import { verifyJwt } from '../verifyJwt';
import { db } from '../firebase';
import { sendVoipNotification } from '../utils/sendVoipNotification';

export const scheduledCallRouter = express.Router();
scheduledCallRouter.use(verifyJwt);

scheduledCallRouter.post('/call', async (req, res) => {
  const uid = (req as any).uid;
  const { partnerId, channelName } = req.body;

  if (!partnerId || !channelName) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    // Optionally lookup user info
    const userDoc = await db.collection('user_metadata').doc(uid).get();
    const username = userDoc.data()?.username ?? 'Anonymous';

    await sendVoipNotification(partnerId, {
      title: 'Incoming Scheduled Call',
      body: `${username} wants to start your scheduled call now.`,
      data: {
        type: 'call',
        channelName,
        callerId: uid,
        callerName: username,
      },
    });

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('❌ Failed to send scheduled call push:', err);
    return res.status(500).json({ error: 'Failed to send call' });
  }
});
