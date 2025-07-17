import admin from 'firebase-admin';

admin.initializeApp({
  credential: admin.credential.applicationDefault(),
    storageBucket: process.env.FIREBASE_BUCKET,
});

export const db = admin.firestore();
export const auth = admin.auth();
