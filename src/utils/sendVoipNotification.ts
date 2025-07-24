import { messaging, db } from '../firebase';

export async function sendVoipNotification(uid: string, payload: any) {
  console.log('📡 Attempting VoIP push to:', uid);

  const snap = await db.collection('users').doc(uid).collection('pushTokens').get();
  const tokens = snap.docs.map(d => d.id);

  if (!tokens.length) {
    console.warn('⚠️ No push tokens found for user:', uid);
    return;
  }

  console.log(`📲 Sending VoIP to ${tokens.length} device(s):`, tokens);

  const messages = tokens.map(token => ({
  token,
  notification: {
    title: payload.title,
    body: payload.body,
  },
  data: payload.data,
  android: {
    priority: 'high' as const, // ✅ FIX HERE
    notification: {
      channelId: 'call_channel',
      sound: 'default',
    },
  },
  apns: {
    headers: {
      'apns-priority': '10',
    },
    payload: {
      aps: {
        sound: 'default',
        category: 'incoming_call',
        contentAvailable: true,
      },
    },
  },
}));


  try {
    const response = await messaging.sendEach(messages);
    console.log('✅ VoIP push response:', response);

    if (response.failureCount > 0) {
      response.responses.forEach((resp, idx) => {
        if (!resp.success) {
          console.error(`❌ Token ${tokens[idx]} failed:`, resp.error);
        }
      });
    }
  } catch (err) {
    console.error('❌ Failed to send push messages:', err);
  }
}


