import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const matchActionsRouter = express.Router();
matchActionsRouter.use(verifyJwt);

matchActionsRouter.post('/accept', async (req, res) => {
  const uid = (req as any).uid;
  const docRef = db.collection('matchQueue').doc(uid);
  const doc = await docRef.get();

  if (!doc.exists) return res.status(404).json({ error: 'Not in queue' });

  const data = doc.data();
  if (!data || data.state !== 'match-pending') {
    return res.status(400).json({ error: 'No pending match' });
  }

  await docRef.update({ state: 'match-accepted-pending', accepted: true });

  const partnerRef = db.collection('matchQueue').doc(data.partnerId);
  const partnerDoc = await partnerRef.get();

  if (!partnerDoc.exists) return res.status(200).json({ status: 'waiting' });

  const partnerData = partnerDoc.data();
  if (!partnerData) return res.status(200).json({ status: 'waiting' });

  if (partnerData.accepted) {
    const callRef = await db.collection('calls').add({
      users: [uid, data.partnerId],
      channelName: data.channelName,
      active: true,
      startedAt: Date.now(),
    });

    const callId = callRef.id;

    await Promise.all([
      docRef.update({ state: 'matched', callId }),
      partnerRef.update({ state: 'matched', callId }),
      db.collection('users')
        .doc(uid)
        .collection('user-metadata')
        .doc('matches')
        .set(
          {
            [data.partnerId]: { matched: true, timestamp: Date.now() },
          },
          { merge: true }
        ),
      db.collection('users')
        .doc(data.partnerId)
        .collection('user-metadata')
        .doc('matches')
        .set(
          {
            [uid]: { matched: true, timestamp: Date.now() },
          },
          { merge: true }
        ),
    ]);

    console.log('✅ Match completed between', uid, 'and', data.partnerId);

    return res.status(200).json({ status: 'matched', callId });
  }

  return res.status(200).json({ status: 'waiting' });
});

matchActionsRouter.post('/decline', async (req, res) => {
  const uid = (req as any).uid;
  const docRef = db.collection('matchQueue').doc(uid);
  const doc = await docRef.get();

  if (!doc.exists) return res.status(404).json({ error: 'Not in queue' });

  const data = doc.data();
  if (!data?.partnerId) return res.status(400).json({ error: 'No match to decline' });

  const partnerId = data.partnerId;
  const partnerRef = db.collection('matchQueue').doc(partnerId);

  await Promise.all([
    docRef.update({
      state: 'searching',
      partnerId: null,
      channelName: null,
      accepted: false,
    }),
    partnerRef.update({
      state: 'searching',
      partnerId: null,
      channelName: null,
      accepted: false,
    }),
  ]);

  const now = Date.now();
  const userMetadataRef = db
    .collection('users')
    .doc(uid)
    .collection('user-metadata')
    .doc('matches');

  const partnerMetadataRef = db
    .collection('users')
    .doc(partnerId)
    .collection('user-metadata')
    .doc('matches');

  await Promise.all([
    userMetadataRef.set(
      {
        [partnerId]: { declined: true, timestamp: now },
      },
      { merge: true }
    ),
    partnerMetadataRef.set(
      {
        [uid]: { declined: true, timestamp: now },
      },
      { merge: true }
    ),
  ]);

  console.log('❌ Match declined by', uid);

  return res.status(200).json({ status: 'declined' });
});

matchActionsRouter.post('/call/end', async (req, res) => {
  const { callId } = req.body;
  if (!callId) return res.status(400).json({ error: 'Missing callId' });

  await db.collection('calls').doc(callId).update({
    active: false,
    endedAt: Date.now(),
  });

  console.log('📞 Call ended:', callId);

  return res.status(200).json({ status: 'ended' });
});
