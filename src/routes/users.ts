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
      bioResponses: metadata?.bioResponses ?? {},
      onboardingStage: metadata?.onboardingStage ?? 'bio',
      groupCodes: metadata?.groupCodes ?? [],
      themeMode: metadata?.themeMode ?? null,
      textScale: metadata?.textScale ?? null,
      currentPrompt: metadata?.currentPrompt ?? null,
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
  const { joinedPools, blockedCategories, groupCodes } = req.body;

  if (!Array.isArray(joinedPools) || !Array.isArray(blockedCategories)) {
    return res.status(400).json({ error: 'Invalid format' });
  }

  try {
    const update: any = { joinedPools, blockedCategories };
    if (Array.isArray(groupCodes)) {
      update.groupCodes = groupCodes.filter((c: any) => typeof c === 'string');
    }
    await db.collection('user_metadata').doc(uid).update(update);

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
  const { username, photoUrl, bioResponses, onboardingStage, themeMode, textScale, groupCodes, currentPrompt, connectOutsidePreferences } = req.body;

// Check individual fields before merging
const updatePayload: any = {};
if (username) updatePayload.username = username;
if (photoUrl) updatePayload.photoUrl = photoUrl;
if (bioResponses) updatePayload.bioResponses = bioResponses;
if (onboardingStage) updatePayload.onboardingStage = onboardingStage;
 if (themeMode) updatePayload.themeMode = themeMode;
 if (typeof textScale === 'number') updatePayload.textScale = textScale;
 if (Array.isArray(groupCodes)) updatePayload.groupCodes = groupCodes.filter((c: any) => typeof c === 'string');
 if (typeof currentPrompt === 'string') updatePayload.currentPrompt = currentPrompt;
 if (typeof connectOutsidePreferences === 'boolean') updatePayload.connectOutsidePreferences = connectOutsidePreferences;

try {
  await db.collection('user_metadata').doc(uid).set(updatePayload, { merge: true });
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

usersRouter.get('/:uid', async (req, res) => {
  const { uid } = req.params;

  try {
    const doc = await db.collection('user_metadata').doc(uid).get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });

    return res.status(200).json(doc.data());
  } catch (e) {
    console.error(`❌ Failed to fetch metadata for ${uid}:`, e);
    return res.status(500).json({ error: 'Failed to load user metadata' });
  }
});

usersRouter.get('/:uid/reviews', async (req, res) => {
  const { uid } = req.params;

  try {
    const doc = await db.collection('users').doc(uid).collection('user-metadata').doc('reviews').get();
    if (!doc.exists) return res.json({ average: 0, count: 0 });

    const data = doc.data();
    const ratings = Object.values(data || {}).map((entry: any) => entry.rating).filter((r) => typeof r === 'number');

    const average = ratings.length
      ? ratings.reduce((sum, r) => sum + r, 0) / ratings.length
      : 0;

    return res.status(200).json({ average, count: ratings.length });
  } catch (e) {
    console.error(`❌ Failed to load reviews for ${uid}:`, e);
    return res.status(500).json({ error: 'Failed to fetch reviews' });
  }
});

usersRouter.post('/review', verifyJwt, async (req, res) => {
  const uid = (req as any).uid;
  const { partnerId, channelName, rating, comment, superlatives } = req.body;

  if (!partnerId || !channelName || rating === undefined) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const reviewData: any = {
      rating,
      comment,
      timestamp: Date.now(),
    };

    if (Array.isArray(superlatives) && superlatives.length > 0) {
      reviewData.superlatives = superlatives;
    }

    await db.collection('users')
      .doc(partnerId)
      .collection('user-metadata')
      .doc('reviews')
      .set({ [uid]: reviewData }, { merge: true });

    // ✅ Mark as reviewed
    const callSnap = await db.collection('users')
      .doc(uid)
      .collection('user-metadata')
      .doc('history')
      .collection('calls')
      .where('partnerId', '==', partnerId)
      .where('channelName', '==', channelName)
      .limit(1)
      .get();

    if (!callSnap.empty) {
      await callSnap.docs[0].ref.update({ reviewed: true });
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Review submission failed:', e);
    return res.status(500).json({ error: 'Failed to submit review' });
  }
});
