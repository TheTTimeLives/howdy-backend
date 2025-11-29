import { db } from '../firebase';

export const matchUsers = async () => {
  const queueRef = db.collection('matchQueue');
  const waitingSnapshot = await queueRef
    .where('state', '==', 'searching')
    .orderBy('timestamp')
    .get();

  const users = waitingSnapshot.docs;

  for (let i = 0; i < users.length; i++) {
    const user = users[i];
    const uid = user.id;
    const userData = user.data();

    const userMetadataSnap = await db
      .collection('users')
      .doc(uid)
      .collection('user-metadata')
      .doc('matches')
      .get();

    const previouslyMatched = userMetadataSnap.exists
      ? userMetadataSnap.data() ?? {}
      : {};

    for (let j = i + 1; j < users.length; j++) {
      const candidate = users[j];
      const candidateId = candidate.id;
      const candidateData = candidate.data();

      if (previouslyMatched[candidateId]?.declined) continue;

      const candidateMetadataSnap = await db
        .collection('users')
        .doc(candidateId)
        .collection('user-metadata')
        .doc('matches')
        .get();

      const candidateDeclined = candidateMetadataSnap.exists
        ? candidateMetadataSnap.data() ?? {}
        : {};

      if (candidateDeclined[uid]?.declined) continue;

      const channelName = `channel_${Date.now()}`;

      await Promise.all([
        queueRef.doc(uid).update({
          state: 'match-pending',
          partnerId: candidateId,
          channelName,
          accepted: false,
          timestamp: Date.now(),
          topic: candidate.data().prefs?.topic || null, // ✅ show THEIR topic
        }),
        queueRef.doc(candidateId).update({
          state: 'match-pending',
          partnerId: uid,
          channelName,
          accepted: false,
          timestamp: Date.now(),
          topic: user.data().prefs?.topic || null, // ✅ show THEIR topic
        }),
      ]);


      return;
    }
  }
};
