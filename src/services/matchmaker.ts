import { db } from '../firebase';

/**
 * Check if two users are romantically compatible based on gender preferences
 */
function areRomanticallyCompatible(
  user1Gender: string,
  user1Interest: string,
  user2Gender: string,
  user2Interest: string
): boolean {
  // If either hasn't set preferences, default to not romantically compatible
  if (!user1Gender || !user1Interest || !user2Gender || !user2Interest) {
    return false;
  }

  // Check if user1 is interested in user2's gender
  const user1InterestedInUser2 =
    user1Interest === 'everyone' ||
    (user1Interest === 'men' && user2Gender === 'male') ||
    (user1Interest === 'women' && user2Gender === 'female');

  // Check if user2 is interested in user1's gender
  const user2InterestedInUser1 =
    user2Interest === 'everyone' ||
    (user2Interest === 'men' && user1Gender === 'male') ||
    (user2Interest === 'women' && user1Gender === 'female');

  return user1InterestedInUser2 && user2InterestedInUser1;
}

/**
 * Calculate the match type based on both users' preferences
 * Returns 'friends' if either only wants friends OR if gender preferences don't align
 * Returns 'romance' only if both are open to romance AND gender preferences align
 */
function calculateMatchType(
  user1Intent: string,
  user1Gender: string,
  user1Interest: string,
  user2Intent: string,
  user2Gender: string,
  user2Interest: string
): 'friends' | 'romance' {
  // Default to friends if not set
  const intent1 = user1Intent || 'friends';
  const intent2 = user2Intent || 'friends';

  // If either only wants friends, match type is friends
  if (intent1 === 'friends' || intent2 === 'friends') {
    return 'friends';
  }

  // Both are open to romance (have 'romance' or 'both')
  // Check if their gender preferences align
  if (areRomanticallyCompatible(user1Gender, user1Interest, user2Gender, user2Interest)) {
    return 'romance';
  }

  // Gender preferences don't align, so it's a friendship match
  return 'friends';
}

export const matchUsers = async () => {
  const queueRef = db.collection('matchQueue');
  
  // First, handle users in "waiting-for-rematch" state
  // Check for expired rematch windows
  const now = Date.now();
  const rematchingSnapshot = await queueRef
    .where('state', '==', 'waiting-for-rematch')
    .get();

  for (const doc of rematchingSnapshot.docs) {
    const data = doc.data();
    if (data.rematchDeadline && data.rematchDeadline < now) {
      // Timeout expired, transition to "rematch-timeout"
      await queueRef.doc(doc.id).update({
        state: 'rematch-timeout',
        timestamp: now,
      });
      console.log(`⏰ ${doc.id} rematch window expired, transitioned to rematch-timeout`);
    }
  }

  // Now transition any "rematch-timeout" users back to "searching"
  const timeoutSnapshot = await queueRef
    .where('state', '==', 'rematch-timeout')
    .get();

  for (const doc of timeoutSnapshot.docs) {
    await queueRef.doc(doc.id).update({
      state: 'searching',
      timestamp: now,
      rematchDeadline: null,
    });
    console.log(`🔄 ${doc.id} transitioned from rematch-timeout back to searching`);
  }

  // Fetch all users in "waiting-for-rematch" (not expired)
  const rematchingUsersSnapshot = await queueRef
    .where('state', '==', 'waiting-for-rematch')
    .orderBy('timestamp')
    .get();

  // Fetch all users actively searching
  const waitingSnapshot = await queueRef
    .where('state', '==', 'searching')
    .orderBy('timestamp')
    .get();

  const rematchingUsers = rematchingUsersSnapshot.docs;
  const users = waitingSnapshot.docs;

  // Try to match "waiting-for-rematch" users first (they have priority)
  for (const rematchUser of rematchingUsers) {
    const rematchUid = rematchUser.id;
    const rematchData = rematchUser.data();

    // Skip if deadline expired (should have been caught above, but double-check)
    if (rematchData.rematchDeadline && rematchData.rematchDeadline < now) {
      continue;
    }

    // Fetch rematch user's preferences
    const rematchPrefsSnap = await db
      .collection('users')
      .doc(rematchUid)
      .collection('user-metadata')
      .doc('user-metadata')
      .get();
    const rematchPrefs = rematchPrefsSnap.exists ? rematchPrefsSnap.data() : {};

    const rematchMetadataSnap = await db
      .collection('users')
      .doc(rematchUid)
      .collection('user-metadata')
      .doc('matches')
      .get();
    const rematchPreviouslyMatched = rematchMetadataSnap.exists
      ? rematchMetadataSnap.data() ?? {}
      : {};

    // Try to match with searching users
    for (const searchingUser of users) {
      const candidateId = searchingUser.id;
      const candidateData = searchingUser.data();

      // Skip if previously declined
      if (rematchPreviouslyMatched[candidateId]?.declined) continue;

      // Fetch candidate's preferences
      const candidatePrefsSnap = await db
        .collection('users')
        .doc(candidateId)
        .collection('user-metadata')
        .doc('user-metadata')
        .get();
      const candidatePrefs = candidatePrefsSnap.exists ? candidatePrefsSnap.data() : {};

      const candidateMetadataSnap = await db
        .collection('users')
        .doc(candidateId)
        .collection('user-metadata')
        .doc('matches')
        .get();
      const candidateDeclined = candidateMetadataSnap.exists
        ? candidateMetadataSnap.data() ?? {}
        : {};

      if (candidateDeclined[rematchUid]?.declined) continue;

      // Calculate match type
      const matchType = calculateMatchType(
        rematchPrefs?.matchingIntent || 'friends',
        rematchPrefs?.gender || '',
        rematchPrefs?.genderInterest || '',
        candidatePrefs?.matchingIntent || 'friends',
        candidatePrefs?.gender || '',
        candidatePrefs?.genderInterest || ''
      );

      const channelName = `channel_${Date.now()}`;

      // Create the match
      await Promise.all([
        queueRef.doc(rematchUid).update({
          state: 'match-pending',
          partnerId: candidateId,
          channelName,
          accepted: false,
          timestamp: Date.now(),
          rematchDeadline: null, // Clear deadline
          declinedBy: null, // Clear declined tracking
          topic: candidateData.prefs?.topic || null,
          matchType,
          partnerMatchingIntent: candidatePrefs?.matchingIntent || 'friends',
        }),
        queueRef.doc(candidateId).update({
          state: 'match-pending',
          partnerId: rematchUid,
          channelName,
          accepted: false,
          timestamp: Date.now(),
          topic: rematchData.prefs?.topic || null,
          matchType,
          partnerMatchingIntent: rematchPrefs?.matchingIntent || 'friends',
        }),
      ]);

      console.log(`✨ Rematched ${rematchUid} with ${candidateId} as ${matchType}`);
      return; // Exit after successful rematch
    }
  }

  // Regular matching for searching users
  for (let i = 0; i < users.length; i++) {
    const user = users[i];
    const uid = user.id;
    const userData = user.data();

    // Fetch user's preferences (intent, gender, genderInterest)
    const userPrefsSnap = await db
      .collection('users')
      .doc(uid)
      .collection('user-metadata')
      .doc('user-metadata')
      .get();
    const userPrefs = userPrefsSnap.exists ? userPrefsSnap.data() : {};

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

      // Fetch candidate's preferences
      const candidatePrefsSnap = await db
        .collection('users')
        .doc(candidateId)
        .collection('user-metadata')
        .doc('user-metadata')
        .get();
      const candidatePrefs = candidatePrefsSnap.exists ? candidatePrefsSnap.data() : {};

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

      // Calculate the match type based on both users' preferences
      const matchType = calculateMatchType(
        userPrefs?.matchingIntent || 'friends',
        userPrefs?.gender || '',
        userPrefs?.genderInterest || '',
        candidatePrefs?.matchingIntent || 'friends',
        candidatePrefs?.gender || '',
        candidatePrefs?.genderInterest || ''
      );

      const channelName = `channel_${Date.now()}`;

      await Promise.all([
        queueRef.doc(uid).update({
          state: 'match-pending',
          partnerId: candidateId,
          channelName,
          accepted: false,
          timestamp: Date.now(),
          topic: candidate.data().prefs?.topic || null,
          matchType, // Store the calculated match type
          partnerMatchingIntent: candidatePrefs?.matchingIntent || 'friends', // Show partner's intent
        }),
        queueRef.doc(candidateId).update({
          state: 'match-pending',
          partnerId: uid,
          channelName,
          accepted: false,
          timestamp: Date.now(),
          topic: user.data().prefs?.topic || null,
          matchType, // Store the calculated match type
          partnerMatchingIntent: userPrefs?.matchingIntent || 'friends', // Show partner's intent
        }),
      ]);

      console.log(`✅ Matched ${uid} and ${candidateId} as ${matchType}`);
      return;
    }
  }
};
