import express from 'express';
import { verifyJwt } from '../verifyJwt';
import { db } from '../firebase';
import { sendVoipNotification } from '../utils/sendVoipNotification';

export const scheduledCallRouter = express.Router();
scheduledCallRouter.use(verifyJwt);

// GET /scheduled/list - scheduled calls involving current user
scheduledCallRouter.get('/list', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const statuses = ['accept', 'accepted'];
    const q1 = await db.collection('events').where('status', 'in', statuses).where('partnerId', '==', uid).get();
    const q2 = await db.collection('events').where('status', 'in', statuses).where('senderId', '==', uid).get();
    const now = Date.now();
    const merged = [...q1.docs, ...q2.docs].map((d) => ({ id: d.id, ...(d.data() as any) }));
    // de-duplicate by id
    const byId: Record<string, any> = {};
    for (const row of merged) byId[row.id] = row;
    const rows = Object.values(byId)
      .filter((e: any) => typeof e.start === 'number' && typeof e.end === 'number' && e.channelName)
      .map((e: any) => {
        const start = Number(e.start);
        const end = Number(e.end);
        return {
          id: e.id,
          senderId: e.senderId,
          partnerId: e.partnerId,
          channelName: e.channelName,
          start,
          end,
          inWindow: now >= start && now <= end,
          secondsUntilStart: now < start ? Math.max(0, Math.floor((start - now) / 1000)) : 0,
        };
      })
      .sort((a: any, b: any) => a.start - b.start)
      .slice(0, 50);
    return res.status(200).json({ calls: rows });
  } catch (e) {
    console.error('❌ list scheduled calls failed', e);
    return res.status(500).json({ error: 'Failed to list scheduled calls' });
  }
});

scheduledCallRouter.post('/call', async (req, res) => {
  const uid = (req as any).uid;
  const { partnerId, channelName } = req.body;

  console.log('📨 Scheduled Call Triggered', { from: uid, to: partnerId, channelName });

  if (!partnerId || !channelName) {
    console.warn('❌ Missing partnerId or channelName');
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    const userDoc = await db.collection('user_metadata').doc(uid).get();
    const username = userDoc.data()?.username ?? 'Anonymous';

    console.log('👤 Caller username resolved:', username);

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

    console.log('✅ VoIP push attempted to', partnerId);

    return res.status(200).json({ ok: true });
  } catch (err) {
    console.error('❌ Failed to send scheduled call push:', err);
    return res.status(500).json({ error: 'Failed to send call' });
  }
});

