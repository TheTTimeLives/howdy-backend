import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import axios from 'axios';
import * as admin from 'firebase-admin';
import { v4 as uuidv4 } from 'uuid';
import path from 'path';

const TENOR_API_KEY = process.env.TENOR_API_KEY;
const TENOR_CLIENT_KEY = 'howdy-app-123';

export const usersRouter = express.Router();
usersRouter.use(verifyJwt);

usersRouter.get('/me', async (req, res) => {
  const uid = (req as any).uid;

  try {
    const metadataDoc = await db.collection('user_metadata').doc(uid).get();
    if (!metadataDoc.exists) {
      return res.status(404).json({ error: 'User metadata not found' });
    }

    const metadata = metadataDoc.data();
    const joinedPoolIds: string[] = metadata?.joinedPools || [];
    const blockedCategoryIds: string[] = metadata?.blockedCategories || [];

    // Prepare joinedPools
    let joinedPools: { id: string; name: string }[] = [];
    if (joinedPoolIds.length > 0) {
      const poolDocs = await db.getAll(
        ...joinedPoolIds.map((id) => db.collection('pools').doc(id))
      );
      joinedPools = poolDocs
        .filter((doc) => doc.exists)
        .map((doc) => ({
          id: doc.id,
          name: doc.data()?.name ?? doc.id,
        }));
    }

    // Prepare blockedCategories
    let blockedCategories: { id: string; name: string }[] = [];
    if (blockedCategoryIds.length > 0) {
      const catDocs = await db.getAll(
        ...blockedCategoryIds.map((id) => db.collection('categories').doc(id))
      );
      blockedCategories = catDocs
        .filter((doc) => doc.exists)
        .map((doc) => ({
          id: doc.id,
          name: doc.data()?.name ?? doc.id,
        }));
    }

    // 🧠 Determine profile image type
    const photoUrl = metadata?.photoUrl;
    const photoType = photoUrl?.startsWith('assets/')
      ? 'asset'
      : photoUrl?.startsWith('http')
        ? 'hosted'
        : null;

    return res.status(200).json({
      username: metadata?.username ?? '',
      photoUrl,
      photoType,
      joinedPools,
      blockedCategories,
      verificationStatus: metadata?.verificationStatus ?? 'awaiting',
      onboarded: metadata?.onboarded ?? false,
      connectionCount: metadata?.connectionCount ?? 0,
      connectOutsidePreferences: metadata?.connectOutsidePreferences ?? false,
    });
  } catch (e) {
    console.error('❌ Fetch error:', e);
    return res.status(500).json({ error: 'Failed to fetch user metadata' });
  }
});


usersRouter.post('/verification/reset', async (req, res) => {
  const uid = (req as any).uid;
  try {
    await db.collection('user_metadata').doc(uid).update({
      verificationStatus: 'awaiting',
    });
    res.status(200).json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to reset verification status' });
  }
});

usersRouter.post('/preferences', async (req, res) => {
  const uid = (req as any).uid;
  const { joinedPools, blockedCategories } = req.body;

  if (!Array.isArray(joinedPools) || !Array.isArray(blockedCategories)) {
    return res.status(400).json({ error: 'Invalid format' });
  }

  try {
    await db.collection('user_metadata').doc(uid).update({
      joinedPools,
      blockedCategories,
    });

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Failed to update preferences:', e);
    res.status(500).json({ error: 'Failed to update preferences' });
  }
});

usersRouter.get('/tenor/search', async (req, res) => {
  const { q, limit } = req.query;

  if (!q || typeof q !== 'string') {
    return res.status(400).json({ error: 'Missing or invalid query param "q"' });
  }

  if (!TENOR_API_KEY) {
    console.error('❌ TENOR_API_KEY is missing from .env');
    return res.status(500).json({ error: 'Server misconfiguration' });
  }

  try {
    const r = await axios.get('https://tenor.googleapis.com/v2/search', {
      params: {
        key: TENOR_API_KEY,
        client_key: TENOR_CLIENT_KEY,
        q,
        limit: limit || 15,
        media_filter: 'minimal',
        contentfilter: 'medium',
      },
    });

    const gifs = r.data.results.map((result: any) =>
      result?.media_formats?.gifpreview?.url ??
      result?.media_formats?.tinygifpreview?.url
    ).filter((url: string | null) => !!url);

    res.status(200).json({ gifs });
  } catch (e) {
    console.error('❌ Tenor search failed:', e);
    res.status(500).json({ error: 'Tenor search failed' });
  }
});


usersRouter.post('/metadata', async (req, res) => {
  const uid = (req as any).uid;
  const { username, photoUrl } = req.body;

  if (!username || !photoUrl) {
    return res.status(400).json({ error: 'Missing username or photoUrl' });
  }

  try {
    await db.collection('user_metadata').doc(uid).set({
      username,
      photoUrl,
      onboarded: true,
    }, { merge: true }); // ✅ merge ensures it won’t overwrite unrelated fields

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Failed to update metadata:', e);
    return res.status(500).json({ error: 'Failed to update user metadata' });
  }
});

usersRouter.post('/metadata', async (req, res) => {
  const uid = (req as any).uid;
  const { username, photoUrl } = req.body;

  if (!username || !photoUrl) {
    return res.status(400).json({ error: 'Missing username or photoUrl' });
  }

  const isAsset = photoUrl.startsWith('assets/'); // local static asset path

  try {
    const userDoc = db.collection('user_metadata').doc(uid);
    const existing = await userDoc.get();
    const oldPath = existing.data()?.photoStoragePath;

    let finalPhotoUrl = photoUrl;
    let finalStoragePath = undefined;

    // 🔁 Delete previous Firebase image (if any)
    if (oldPath) {
      try {
        await admin.storage().bucket().file(oldPath).delete();
        console.log(`🗑 Deleted previous avatar: ${oldPath}`);
      } catch (err) {
        console.warn('⚠️ Could not delete old image:', err);
      }
    }

    // 🧠 If it's a Tenor image, proxy and upload it to Firebase Storage
    if (!isAsset && photoUrl.startsWith('http')) {
      const axiosResp = await axios.get(photoUrl, { responseType: 'arraybuffer' });
      const buffer = Buffer.from(axiosResp.data, 'binary');

      const ext = path.extname(new URL(photoUrl).pathname).replace('.', '') || 'jpg';
      const filename = `profile-images/${uid}.${ext}`;

      const file = admin.storage().bucket().file(filename);
      await file.save(buffer, {
        metadata: {
          contentType: `image/${ext}`,
          metadata: {
            firebaseStorageDownloadTokens: uuidv4(),
          },
        },
        public: true,
      });

      finalPhotoUrl = `https://storage.googleapis.com/${file.bucket.name}/${file.name}`;
      finalStoragePath = filename;
    }

    // ✅ Save user metadata
    await userDoc.set({
      username,
      photoUrl: finalPhotoUrl,
      photoStoragePath: finalStoragePath,
      onboarded: true,
    }, { merge: true });

    return res.status(200).json({ ok: true, photoUrl: finalPhotoUrl });
  } catch (e) {
    console.error('❌ Failed to update metadata:', e);
    return res.status(500).json({ error: 'Failed to process avatar' });
  }
});