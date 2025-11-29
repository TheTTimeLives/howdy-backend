import express from 'express';
import { db } from '../firebase';
import { sendVoipNotification } from '../utils/sendVoipNotification';
import { decryptString } from '../utils/pii';
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
    // Debug log to trace routing inputs
    try {
      console.log(
        '[USERS /me] uid=%s verified=%s acct=%s stage=%s group=%s',
        uid,
        metadata?.verificationStatus ?? 'awaiting',
        metadata?.accountType ?? 'individual',
        metadata?.onboardingStage ?? 'bio',
        metadata?.primaryGroupId ?? null
      );
    } catch (_e) {
      // ignore log errors
    }
    const userDoc = await db.collection('users').doc(uid).get();
    const userData = userDoc.data() || {};
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

    let firstName: string | null = null;
    let lastName: string | null = null;
    if (userData?.pii) {
      console.log('🔊 userData.pii:', userData.pii);
      if (typeof userData.pii.firstNameEnc === 'string') {
        firstName = decryptString(userData.pii.firstNameEnc);
      }
      if (typeof userData.pii.lastNameEnc === 'string') {
        lastName = decryptString(userData.pii.lastNameEnc);
      }
    }

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
      accountType: metadata?.accountType ?? 'individual',
      primaryGroupId: metadata?.primaryGroupId ?? null,
      unmanagedSince: metadata?.unmanagedSince ?? null,
      unmanagedDeleteAt: metadata?.unmanagedSince ? Number(metadata?.unmanagedSince) + (7 * 24 * 60 * 60 * 1000) : null,
      themeMode: metadata?.themeMode ?? null,
      textScale: metadata?.textScale ?? null,
      currentPrompt: metadata?.currentPrompt ?? null,
      ui: metadata?.ui ?? null,
      mfa: metadata?.mfa ? {
        required: !!metadata?.mfa?.required,
        methods: Array.isArray(metadata?.mfa?.methods) ? metadata?.mfa?.methods : [],
      } : { required: false, methods: [] },
      // Expose decrypted names if present; otherwise null
      firstName,
      lastName,
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
    const update: any = { joinedPools, blockedCategories };
    await db.collection('user_metadata').doc(uid).update(update);

    res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Failed to update preferences:', e);
    res.status(500).json({ error: 'Failed to update preferences' });
  }
});

usersRouter.get('/tenor/search', async (req, res) => {
  console.log('🔍 Tenor search request:', req.query);
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

    console.log('🔍 Tenor search response:', { gifs });
    res.status(200).json({ gifs });
  } catch (e) {
    console.error('❌ Tenor search failed:', e);
    res.status(500).json({ error: 'Tenor search failed' });
  }
});


usersRouter.post('/metadata', async (req, res) => {
  const uid = (req as any).uid;
  const { username, photoUrl, bioResponses, onboardingStage, themeMode, textScale, currentPrompt, connectOutsidePreferences } = req.body;

// Check individual fields before merging
const updatePayload: any = {};
if (username) updatePayload.username = username;
if (photoUrl) updatePayload.photoUrl = photoUrl;
if (bioResponses) updatePayload.bioResponses = bioResponses;
if (onboardingStage) updatePayload.onboardingStage = onboardingStage;
 if (themeMode) updatePayload.themeMode = themeMode;
 if (typeof textScale === 'number') updatePayload.textScale = textScale;
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

// POST /users/device-status  { platform, policyAccessGranted, interruptionFilter, ringerMode, reportedAt }
usersRouter.post('/device-status', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const payload = {
      deviceStatus: {
        platform: String(req.body?.platform || 'unknown'),
        policyAccessGranted: !!req.body?.policyAccessGranted,
        interruptionFilter: typeof req.body?.interruptionFilter === 'number' ? req.body.interruptionFilter : null,
        ringerMode: typeof req.body?.ringerMode === 'number' ? req.body.ringerMode : null,
        reportedAt: typeof req.body?.reportedAt === 'number' ? req.body.reportedAt : Date.now(),
      }
    };
    await db.collection('user_metadata').doc(uid).set(payload, { merge: true });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('[device-status] failed', e);
    return res.status(500).json({ error: 'Failed to record device status' });
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

    // ✅ Removed transcript submission from review flow to avoid duplicates.

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Review submission failed:', e);
    return res.status(500).json({ error: 'Failed to submit review' });
  }
});

// ---- Chi endpoints ----
const DEFAULT_THRESHOLDS = (process.env.CHI_LEVEL_THRESHOLDS || '100,250,500,1000,2000')
  .split(',')
  .map((s) => parseInt(s.trim(), 10))
  .filter((n) => !isNaN(n))
  .sort((a, b) => a - b);

function computeLevel(total: number): number {
  let level = 0;
  for (const t of DEFAULT_THRESHOLDS) {
    if (total >= t) level += 1; else break;
  }
  return level;
}

usersRouter.get('/chi/me', verifyJwt, async (req, res) => {
  const uid = (req as any).uid;
  try {
    const meta = await db.collection('user_metadata').doc(uid).get();
    const data = meta.data() || {};
    const chiTotal = data.chiTotal || 0;
    const chiLevel = data.chiLevel || computeLevel(chiTotal);
    const connectionsBank = data.connectionsBank || 0;
    const nextIdx = DEFAULT_THRESHOLDS.find((t) => t > chiTotal);
    return res.status(200).json({ chiTotal, chiLevel, connectionsBank, nextLevelAt: nextIdx ?? null });
  } catch (e) {
    console.error('❌ /users/chi/me failed:', e);
    return res.status(500).json({ error: 'Failed to load chi' });
  }
});

usersRouter.post('/chi/accrue', verifyJwt, async (req, res) => {
  const uid = (req as any).uid;
  const durationSec = Math.floor(Number(req.body?.durationSec || 0));
  if (!durationSec || durationSec < 300) {
    // Require at least 5 minutes
    return res.status(200).json({ ok: true, awarded: 0, reason: 'min_duration' });
  }

  try {
    let responsePayload: any = {};
    await db.runTransaction(async (tx) => {
      const ref = db.collection('user_metadata').doc(uid);
      const snap = await tx.get(ref);
      const data: any = snap.exists ? snap.data() : {};

      // Daily multiplier logic
      const now = new Date();
      const todayKey = now.toISOString().slice(0, 10); // YYYY-MM-DD UTC
      const lastKey = data.chiDailyKey as string | undefined;
      let dailyCount = data.chiDailyCount as number | undefined;
      if (!lastKey || lastKey !== todayKey) {
        dailyCount = 0;
      }
      dailyCount = (dailyCount ?? 0) + 1; // count this completed call

      const multiplier = 1 + Math.min(0.5, Math.max(0, dailyCount - 1) * 0.1); // +10% per additional call today, capped at +50%
      const baseChi = Math.floor(durationSec / 60); // 1 chi per full minute
      const awarded = Math.floor(baseChi * multiplier);

      const prevTotal = data.chiTotal || 0;
      const prevLevel = data.chiLevel ?? computeLevel(prevTotal);
      const prevNextLevelAt = DEFAULT_THRESHOLDS.find((t) => t > prevTotal) ?? null;

      const newTotal = prevTotal + awarded;
      const newLevel = computeLevel(newTotal);
      const newNextLevelAt = DEFAULT_THRESHOLDS.find((t) => t > newTotal) ?? null;
      const levelUps = Math.max(0, newLevel - prevLevel);
      const prevBank = data.connectionsBank || 0;

      tx.set(ref, {
        chiTotal: newTotal,
        chiLevel: newLevel,
        connectionsBank: prevBank + levelUps,
        chiDailyKey: todayKey,
        chiDailyCount: dailyCount,
      }, { merge: true });

      responsePayload = {
        ok: true,
        awarded,
        multiplier,
        prevTotal,
        newTotal,
        prevLevel,
        newLevel,
        prevNextLevelAt,
        newNextLevelAt,
      };
    });

    return res.status(200).json(responsePayload);
  } catch (e) {
    console.error('❌ /users/chi/accrue failed:', e);
    return res.status(500).json({ error: 'Failed to accrue chi' });
  }
});

// ===== Member UI settings (managed by carer/org) =====
usersRouter.get('/members/:memberId/settings', async (req, res) => {
  const requesterUid = (req as any).uid;
  const memberId = String(req.params.memberId || '');
  if (!memberId) return res.status(400).json({ error: 'Missing memberId' });
  try {
    const metaSnap = await db.collection('user_metadata').doc(memberId).get();
    if (!metaSnap.exists) return res.status(404).json({ error: 'Member not found' });
    const data = metaSnap.data() || {};
    if ((data.accountType || '') !== 'member') {
      return res.status(400).json({ error: 'Target user is not a member' });
    }
    const primaryGroupId = data.primaryGroupId;
    const guardianUid = data.guardianUid;
    if (!primaryGroupId && !guardianUid) {
      return res.status(403).json({ error: 'Member is unmanaged' });
    }
    // authorize: guardian or group admin
    let authorized = false;
    if (guardianUid && guardianUid === requesterUid) authorized = true;
    if (!authorized && primaryGroupId) {
      const mem = await db.collection('groups').doc(primaryGroupId).collection('members').doc(requesterUid).get();
      const role = mem.data()?.role || 'member';
      if (['admin', 'super-admin'].includes(String(role))) authorized = true;
    }
    if (!authorized) return res.status(403).json({ error: 'Forbidden' });
    return res.status(200).json({ ui: data.ui || null });
  } catch (e) {
    console.error('❌ GET member settings failed', e);
    return res.status(500).json({ error: 'Failed to load settings' });
  }
});

usersRouter.put('/members/:memberId/settings', async (req, res) => {
  const requesterUid = (req as any).uid;
  const memberId = String(req.params.memberId || '');
  const level = req.body?.level ? String(req.body.level) : undefined;
  const flags = (req.body?.flags && typeof req.body.flags === 'object') ? req.body.flags as Record<string, any> : undefined;
  if (!memberId) return res.status(400).json({ error: 'Missing memberId' });
  try {
    const ref = db.collection('user_metadata').doc(memberId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Member not found' });
    const data = snap.data() || {};
    if ((data.accountType || '') !== 'member') {
      return res.status(400).json({ error: 'Target user is not a member' });
    }
    const primaryGroupId = data.primaryGroupId;
    const guardianUid = data.guardianUid;

    // authorize: guardian or group admin
    let authorized = false;
    if (guardianUid && guardianUid === requesterUid) authorized = true;
    if (!authorized && primaryGroupId) {
      const mem = await db.collection('groups').doc(primaryGroupId).collection('members').doc(requesterUid).get();
      const role = mem.data()?.role || 'member';
      if (['admin', 'super-admin'].includes(String(role))) authorized = true;
    }
    if (!authorized) return res.status(403).json({ error: 'Forbidden' });

    console.log('📝 Updating member UI settings', {
      requesterUid,
      memberId,
      inputLevel: level,
      inputFlags: flags,
    });

    let effectiveFlags = flags && typeof flags === 'object' ? { ...flags } : undefined;
    if (level && (!effectiveFlags || Object.keys(effectiveFlags).length === 0)) {
      // Apply defaults by level if flags not provided
      switch (level.toLowerCase()) {
        case 'assisted':
          effectiveFlags = { allowOutgoingCalls: false, showChat: false, showSchedule: false, showHistory: true };
          break;
        case 'standard':
        case 'full':
          effectiveFlags = { allowOutgoingCalls: true, showChat: true, showSchedule: true, showHistory: true };
          break;
        default:
          break;
      }
    }

    const uiPayload = {
      ui: {
        ...(level ? { level } : {}),
        ...(effectiveFlags ? { flags: effectiveFlags } : {}),
        updatedAt: Date.now(),
        updatedBy: requesterUid,
      }
    };

    console.log('💾 Persisting member UI payload', { memberId, uiPayload });

    await ref.set(uiPayload, { merge: true });

    // Notify the member device(s) to refresh settings
    try {
      console.log('📣 Sending member_ui_updated push to', memberId);
      await sendVoipNotification(memberId, {
        title: 'Settings updated',
        body: 'Your caregiver updated your app settings',
        data: { type: 'member_ui_updated' },
      });
    } catch (e) {
      console.warn('⚠️ Failed to send settings update push:', e);
    }

    console.log('✅ Member UI settings updated', { memberId, level, effectiveFlags });
    return res.status(200).json({ ok: true, level, flags: effectiveFlags });
  } catch (e) {
    console.error('❌ PUT member settings failed', e);
    return res.status(500).json({ error: 'Failed to save settings' });
  }
});