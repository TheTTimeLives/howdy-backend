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
  if (!data) return res.status(400).json({ error: 'Invalid queue state' });

  // If state is 'searching', the partner likely declined before this user clicked accept
  // Put them in waiting-for-rematch state to search for a new match
  if (data.state === 'searching') {
    console.log(`⏳ ${uid} accepted after partner declined, entering waiting-for-rematch`);
    
    // Get user's match wait timeout (default 15 seconds)
    const userMetaDoc = await db.collection('user_metadata').doc(uid).get();
    const matchWaitTimeoutMs = (userMetaDoc.data()?.matchWaitTimeoutSeconds ?? 15) * 1000;
    
    await docRef.update({
      state: 'waiting-for-rematch',
      accepted: false,
      partnerId: null,
      channelName: null,
      rematchDeadline: Date.now() + matchWaitTimeoutMs,
      timestamp: Date.now(),
    });
    
    return res.status(200).json({ status: 'waiting-for-rematch' });
  }

  if (data.state !== 'match-pending') {
    return res.status(400).json({ error: 'No pending match' });
  }

  await docRef.update({ state: 'match-accepted-pending', accepted: true, timestamp: Date.now() });

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
      topicA: data.prefs?.topic || data.topic || null,
      topicB: partnerData?.prefs?.topic || partnerData?.topic || null,
    });

    const callId = callRef.id;

    const callHistoryEntry = (partnerId: string, channelName: string, topic?: string) => ({
      partnerId,
      channelName,
      timestamp: Date.now(),
      reviewed: false, // ✅ Added field
      topic: typeof topic === 'string' ? topic : null,
    });

    await Promise.all([
      docRef.update({ state: 'matched', callId }),
      partnerRef.update({ state: 'matched', callId }),
      db.collection('users')
        .doc(uid)
        .collection('user-metadata')
        .doc('matches')
        .set(
          { [data.partnerId]: { matched: true, timestamp: Date.now() } },
          { merge: true }
        ),
      db.collection('users')
        .doc(data.partnerId)
        .collection('user-metadata')
        .doc('matches')
        .set(
          { [uid]: { matched: true, timestamp: Date.now() } },
          { merge: true }
        ),
      db.collection('users')
        .doc(uid)
        .collection('user-metadata')
        .doc('history')
        .collection('calls')
        .doc(callId)
        .set(callHistoryEntry(data.partnerId, data.channelName, data.prefs?.topic || data.topic)),
      db.collection('users')
        .doc(data.partnerId)
        .collection('user-metadata')
        .doc('history')
        .collection('calls')
        .doc(callId)
        .set(callHistoryEntry(uid, data.channelName, partnerData?.prefs?.topic || partnerData?.topic)),
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
  const partnerDoc = await partnerRef.get();
  const partnerData = partnerDoc.data();

  // Get partner's match wait timeout (default 15 seconds)
  const partnerMetaDoc = await db.collection('user_metadata').doc(partnerId).get();
  const matchWaitTimeoutMs = (partnerMetaDoc.data()?.matchWaitTimeoutSeconds ?? 15) * 1000;

  const now = Date.now();

  // Check if partner already accepted
  const partnerAccepted = partnerData?.accepted === true || partnerData?.state === 'match-accepted-pending';

  if (partnerAccepted) {
    // Partner accepted, this user declined
    // Put partner in "waiting-for-rematch" state for configurable duration
    await partnerRef.update({
      state: 'waiting-for-rematch',
      partnerId: null,
      channelName: null,
      accepted: false,
      rematchDeadline: now + matchWaitTimeoutMs,
      declinedBy: uid, // Track who declined
    });
    console.log(`⏳ ${partnerId} waiting for rematch (${matchWaitTimeoutMs}ms) after ${uid} declined`);
  } else {
    // Neither accepted yet, or both declined simultaneously
    await partnerRef.update({
      state: 'searching',
      partnerId: null,
      channelName: null,
      accepted: false,
    });
  }

  // Declining user goes back to searching
  await docRef.update({
    state: 'searching',
    partnerId: null,
    channelName: null,
    accepted: false,
  });

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
      { [partnerId]: { declined: true, timestamp: now } },
      { merge: true }
    ),
    partnerMetadataRef.set(
      { [uid]: { declined: true, timestamp: now } },
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
