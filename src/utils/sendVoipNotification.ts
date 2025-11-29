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

  // Send DATA-ONLY high-priority messages so the app's background handler
  // can present the native call UI (CallKit/ConnectionService). Avoid the
  // notification field on Android which would bypass the background isolate.
  const messages = tokens.map(token => ({
    token,
    // Include title/body inside data for client-side display if needed
    data: {
      ...(payload?.data || {}),
      title: String(payload?.title || ''),
      body: String(payload?.body || ''),
    },
    android: {
      priority: 'high' as const,
      // Keep channel hint for devices that choose to surface anything
      notification: {
        channelId: 'call_channel',
        sound: 'default',
      },
    },
    apns: {
      headers: {
        // Background data push; the app will raise CallKit locally
        'apns-push-type': 'background',
        'apns-priority': '10',
      },
      payload: {
        aps: {
          // 1 tells iOS it's a background update
          contentAvailable: 1 as any,
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


