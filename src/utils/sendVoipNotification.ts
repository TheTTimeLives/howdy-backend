import { messaging, db } from '../firebase';

export async function sendVoipNotification(uid: string, payload: any) {
  const snap = await db.collection('users').doc(uid).collection('pushTokens').get();
  const tokens = snap.docs.map(d => d.id);

  if (!tokens.length) return;

  const msg = {
  tokens,
  notification: {
    title: payload.title,
    body: payload.body,
  },
  data: payload.data,
  android: {
    priority: 'high' as const, // ✅ TypeScript literal cast
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
};


  await messaging.sendMulticast(msg);
}
