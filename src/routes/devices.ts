import express from 'express';
import { db, auth } from '../firebase';
import admin from 'firebase-admin';
import { verifyJwt } from '../verifyJwt';
import crypto from 'crypto';

export const devicesRouter = express.Router();
devicesRouter.use(express.json());
devicesRouter.use(verifyJwt);
export const devicesPublicRouter = express.Router();
devicesPublicRouter.use(express.json());

// ---- constants --------------------------------------------------------------

const AUDIENCE = 'howdy:device-auth';
const CHALLENGE_TTL_SEC = 60;
const CHALLENGE_MIN_INTERVAL_MS = 3000;   // throttle: 1 challenge / 3s

// ---- helpers ----------------------------------------------------------------

function b64urlToBuffer(input: string): Buffer {
  const s = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  return Buffer.from(s + pad, 'base64');
}
function bufferToB64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}
function safeEq(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}
function prefix(v: string | number | undefined | null, n = 12): string {
  const s = String(v ?? '');
  return s.length <= n ? s : s.slice(0, n) + '…';
}
function rid() { return crypto.randomBytes(4).toString('hex'); }

// Build SPKI from uncompressed EC point for P-256
function jwkToPublicKey(jwk: any): crypto.KeyObject {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' || !jwk.x || !jwk.y) {
    throw new Error('Invalid JWK');
  }
  const x = b64urlToBuffer(String(jwk.x));
  const y = b64urlToBuffer(String(jwk.y));
  if (x.length !== 32 || y.length !== 32) throw new Error('Bad JWK coordinates');
  const uncompressed = Buffer.concat([Buffer.from([0x04]), x, y]);
  // SPKI for prime256v1
  const spkiHead = Buffer.from('3059301306072A8648CE3D020106082A8648CE3D030107034200', 'hex');
  const spki = Buffer.concat([spkiHead, uncompressed]);
  return crypto.createPublicKey({ key: spki, format: 'der', type: 'spki' });
}

// raw (r||s 64) -> DER seq
function rawToDerEcdsaSignature(raw: Buffer): Buffer {
  if (raw.length !== 64) throw new Error('Expected 64-byte raw signature');
  const r = raw.subarray(0, 32);
  const s = raw.subarray(32);
  function i2d(i: Buffer): Buffer {
    let v = i;
    while (v.length > 0 && v[0] === 0x00) v = v.subarray(1);
    if (v.length === 0) v = Buffer.from([0]);
    if (v[0] & 0x80) v = Buffer.concat([Buffer.from([0x00]), v]);
    return Buffer.concat([Buffer.from([0x02, v.length]), v]);
  }
  const seqBody = Buffer.concat([i2d(r), i2d(s)]);
  return Buffer.concat([Buffer.from([0x30, seqBody.length]), seqBody]);
}

// Accept either raw (64) or DER; return DER
function coerceToDer(sigB64url: string): Buffer {
  const buf = b64urlToBuffer(sigB64url);
  if (buf.length === 64) return rawToDerEcdsaSignature(buf);
  if (buf.length >= 70 && buf[0] === 0x30) return buf; // DER seq
  throw new Error('Signature format invalid');
}

function deriveDeviceIdFromJwk(jwk: any): string {
  const x = b64urlToBuffer(String(jwk.x));
  const y = b64urlToBuffer(String(jwk.y));
  const digest = crypto.createHash('sha256').update(Buffer.concat([x, y])).digest();
  return bufferToB64url(digest);
}

function logCtx(ctx: any, msg: string, extra?: Record<string, any>) {
  console.log('[devices]', msg, { ...ctx, ...(extra || {}) });
}

// ---- routes -----------------------------------------------------------------

// PUBLIC: device login challenge { deviceId }
devicesPublicRouter.post('/login/challenge', async (req, res) => {
  const deviceId = String(req.body?.deviceId || '').trim();
  const appSetId = typeof req.body?.appSetId === 'string' ? String(req.body.appSetId).trim() : '';
  const publicKeyJwk = req.body?.publicKeyJwk;
  if (!deviceId) return res.status(400).json({ error: 'Missing deviceId' });
  try {
    let idxRef = db.collection('device_index').doc(deviceId);
    let idxSnap = await idxRef.get();

    // If not found, attempt publisher-scoped anchor recovery via appSetId
    if (!idxSnap.exists && appSetId && publicKeyJwk) {
      const q = await db.collection('device_index')
        .where('appSetId', '==', appSetId)
        .where('status', '==', 'active')
        .limit(2)
        .get();
      if (q.size === 1) {
        const oldDoc = q.docs[0];
        const oldData = oldDoc.data() as any;
        const oldDeviceId = oldDoc.id;
        const uid = String(oldData?.uid || '');
        if (uid) {
          // Rotate: create new index doc under new deviceId, mark old as rotated, update user_metadata.allowedDevice
          const now = Date.now();
          const newIdxRef = db.collection('device_index').doc(deviceId);
          await db.runTransaction(async (tx) => {
            const metaRef = db.collection('user_metadata').doc(uid);
            const metaSnap = await tx.get(metaRef);
            const meta = (metaSnap.data() || {}) as any;
            const allowed = meta.allowedDevice || {};

            // Create/overwrite new index doc
            tx.set(newIdxRef, {
              ...oldData,
              deviceId,
              publicKeyJwk,
              appSetId: appSetId || oldData.appSetId || null,
              registeredAt: now,
              lastSeenAt: null,
              status: 'active',
              prevFrom: oldDeviceId,
              loginChallenge: admin.firestore.FieldValue.delete(), // will set after txn
            }, { merge: true });

            // Mark old as rotated
            tx.set(oldDoc.ref, {
              status: 'rotated',
              rotatedAt: now,
              prevKeys: admin.firestore.FieldValue.arrayUnion({
                deviceId: oldDeviceId,
                publicKeyJwk: oldData?.publicKeyJwk || null,
                rotatedAt: now,
              }),
            }, { merge: true });

            // Update user's allowedDevice
            const prevIds = Array.isArray(allowed.previousDeviceIds) ? allowed.previousDeviceIds : [];
            tx.set(metaRef, {
              allowedDevice: {
                ...allowed,
                deviceId,
                publicKeyJwk,
                previousDeviceIds: admin.firestore.FieldValue.arrayUnion(oldDeviceId),
                anchors: {
                  ...(allowed.anchors || {}),
                  appSetId: appSetId || (allowed.anchors?.appSetId ?? null),
                },
              }
            }, { merge: true });
          });
          // Re-fetch new idxRef for challenge write
          idxRef = newIdxRef;
          idxSnap = await idxRef.get();
        }
      }
      // If zero or multiple matches, fall through and return 404 below
    }

    if (!idxSnap.exists) return res.status(404).json({ error: 'Device not found' });
    const idx = (idxSnap.data() || {}) as any;
    if (idx.status !== 'active' || !idx.uid || !idx.publicKeyJwk) {
      return res.status(403).json({ error: 'Device not active' });
    }

    const lc = idx.loginChallenge || {};
    const lastIssuedAt = Number(lc.issuedAt || 0);
    const nowMs = Date.now();
    if (nowMs - lastIssuedAt < CHALLENGE_MIN_INTERVAL_MS) {
      return res.status(429).json({ error: 'Too many challenges; slow down' });
    }

    const challengeId = crypto.randomBytes(16).toString('hex');
    const nonceBytes = crypto.randomBytes(32);
    const nonceText = bufferToB64url(nonceBytes);
    const nonceHash = bufferToB64url(crypto.createHash('sha256').update(nonceBytes).digest());
    const expSec = Math.floor(nowMs / 1000) + CHALLENGE_TTL_SEC;

    await idxRef.set({ loginChallenge: { jti: challengeId, nonceHash, exp: expSec, issuedAt: nowMs, usedAt: null } }, { merge: true });
    return res.status(200).json({ challengeId, nonce: nonceText, aud: AUDIENCE, exp: CHALLENGE_TTL_SEC });
  } catch (e) {
    console.error('❌ /devices/login/challenge failed', e);
    return res.status(500).json({ error: 'Failed to create challenge' });
  }
});

// PUBLIC: device login prove { deviceId, jws } → { customToken }
devicesPublicRouter.post('/login/prove', async (req, res) => {
  const deviceId = String(req.body?.deviceId || '').trim();
  const jws = String(req.body?.jws || '');
  if (!deviceId || !jws) return res.status(400).json({ error: 'Missing deviceId or jws' });
  try {
    const idxRef = db.collection('device_index').doc(deviceId);
    const idxSnap = await idxRef.get();
    if (!idxSnap.exists) return res.status(404).json({ error: 'Device not found' });
    const idx = (idxSnap.data() || {}) as any;
    if (idx.status !== 'active' || !idx.uid || !idx.publicKeyJwk) {
      return res.status(403).json({ error: 'Device not active' });
    }

    const lc = idx.loginChallenge || {};
    if (!lc.jti || !lc.nonceHash || !lc.exp) return res.status(400).json({ error: 'No outstanding challenge' });
    if (lc.usedAt) return res.status(400).json({ error: 'Challenge already used' });
    if (Math.floor(Date.now() / 1000) > Number(lc.exp)) return res.status(400).json({ error: 'Challenge expired' });

    const parts = jws.split('.');
    if (parts.length !== 3) return res.status(400).json({ error: 'Invalid JWS' });
    const [hB64, pB64, sB64] = parts;
    let header: any, payload: any;
    try { header = JSON.parse(b64urlToBuffer(hB64).toString('utf8')); payload = JSON.parse(b64urlToBuffer(pB64).toString('utf8')); }
    catch { return res.status(400).json({ error: 'Malformed header/payload' }); }
    if (header.alg !== 'ES256') return res.status(400).json({ error: 'Unsupported alg' });

    const now = Math.floor(Date.now() / 1000);
    if (payload.sub !== deviceId) return res.status(400).json({ error: 'Device mismatch' });
    if (payload.aud !== AUDIENCE) return res.status(400).json({ error: 'Bad audience' });
    if (payload.jti !== lc.jti) return res.status(400).json({ error: 'ChallengeId mismatch' });
    if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || payload.exp < now) return res.status(400).json({ error: 'Token expired/invalid' });

    try {
      const nonceBytes = b64urlToBuffer(String(payload.nonce || ''));
      const computedHash = bufferToB64url(crypto.createHash('sha256').update(nonceBytes).digest());
      if (!safeEq(Buffer.from(computedHash), Buffer.from(String(lc.nonceHash)))) return res.status(400).json({ error: 'Nonce mismatch' });
    } catch { return res.status(400).json({ error: 'Nonce malformed' }); }

    let key: crypto.KeyObject;
    try { key = jwkToPublicKey(idx.publicKeyJwk); }
    catch { return res.status(400).json({ error: 'Stored JWK invalid' }); }
    const ok = crypto.verify('sha256', Buffer.from(`${hB64}.${pB64}`, 'utf8'), key, coerceToDer(sB64));
    if (!ok) return res.status(400).json({ error: 'Signature invalid' });

    await idxRef.set({ loginChallenge: { ...lc, usedAt: Date.now() }, lastSeenAt: Date.now() }, { merge: true });

    // Issue Firebase custom token for this member
    const customToken = await auth.createCustomToken(idx.uid, { deviceId });
    return res.status(200).json({ customToken });
  } catch (e) {
    console.error('❌ /devices/login/prove failed', e);
    return res.status(500).json({ error: 'Device login failed' });
  }
});

// POST /devices/register
// Body: { deviceId, publicKeyJwk, platform, osVersion, model, appVersion, pushToken }
devicesRouter.post('/register', async (req, res) => {
  const uid = (req as any).uid as string;
  const ctx = { uid, rid: rid(), step: 'register' };

  const deviceId = String(req.body?.deviceId || '').trim();
  const publicKeyJwk = req.body?.publicKeyJwk;
  const platform = String(req.body?.platform || '').trim().toLowerCase(); // ios|android
  const osVersion = String(req.body?.osVersion || '').trim() || null;
  const model = String(req.body?.model || '').trim() || null;
  const appVersion = String(req.body?.appVersion || '').trim() || null;
  const pushToken = String(req.body?.pushToken || '').trim() || null;
  const appSetId = typeof req.body?.appSetId === 'string' ? String(req.body.appSetId).trim() : null;
  const stableDeviceId = typeof req.body?.stableDeviceId === 'string' ? String(req.body.stableDeviceId).trim() : null;

  if (!deviceId || !publicKeyJwk || !platform) {
    logCtx(ctx, 'invalid body', { platform, deviceIdLen: deviceId?.length || 0, hasJwk: !!publicKeyJwk });
    return res.status(400).json({ error: 'Missing deviceId, publicKeyJwk or platform' });
  }
  if (!['ios', 'android'].includes(platform)) {
    logCtx(ctx, 'bad platform', { platform });
    return res.status(400).json({ error: 'Platform must be ios|android' });
  }

  try {
    try { jwkToPublicKey(publicKeyJwk); }
    catch (e) {
      logCtx(ctx, 'invalid JWK', { err: (e as any)?.message });
      return res.status(400).json({ error: 'Invalid JWK' });
    }

    const derived = deriveDeviceIdFromJwk(publicKeyJwk);
    if (derived !== deviceId) {
      logCtx(ctx, 'deviceId mismatch', { provided: prefix(deviceId), derived: prefix(derived) });
      return res.status(400).json({ error: 'deviceId must be sha256(base64url(x||y)) of the JWK' });
    }

    const metaRef = db.collection('user_metadata').doc(uid);
    const snap = await metaRef.get();
    const meta = (snap.data() || {}) as any;

    if ((meta.accountType || '').toString() !== 'member') {
      logCtx(ctx, 'non-member');
      return res.status(403).json({ error: 'Only member accounts can register a device' });
    }
    if (meta.allowedDevice) {
      logCtx(ctx, 'already registered');
      return res.status(409).json({ error: 'A device is already registered; contact your carer to unpair' });
    }

    const now = Date.now();
    const allowedDevice = {
      deviceId, publicKeyJwk, platform, osVersion, model, appVersion, pushToken,
      registeredAt: now, lastSeenAt: null as number | null, verifiedAt: null as number | null,
      status: 'active' as const,
      anchors: {
        appSetId: appSetId,
        stableDeviceId: stableDeviceId,
      },
      previousDeviceIds: [] as string[],
    };

    await metaRef.set({ allowedDevice, deviceChallenge: null }, { merge: true });
    // Maintain reverse index for public device login
    await db.collection('device_index').doc(deviceId).set({
      uid,
      publicKeyJwk,
      platform,
      osVersion,
      model,
      appVersion,
      pushToken,
      status: 'active',
      registeredAt: now,
      lastSeenAt: null,
      loginChallenge: null,
      appSetId: appSetId,
      stableDeviceId: stableDeviceId,
    }, { merge: true });
    logCtx(ctx, 'register ok', { platform, osVersion, hasPush: !!pushToken });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ /devices/register failed', e);
    return res.status(500).json({ error: 'Failed to register device' });
  }
});

// POST /devices/challenge → issue a one-time challenge for the member's registered device
devicesRouter.post('/challenge', async (req, res) => {
  const uid = (req as any).uid as string;
  const ctx = { uid, rid: rid(), step: 'challenge' };

  try {
    const metaRef = db.collection('user_metadata').doc(uid);
    const snap = await metaRef.get();
    const meta = (snap.data() || {}) as any;

    if ((meta.accountType || '') !== 'member') {
      logCtx(ctx, 'non-member');
      return res.status(403).json({ error: 'Only members can request device challenges' });
    }
    const allowed = meta.allowedDevice;
    if (!allowed || !allowed.publicKeyJwk) {
      logCtx(ctx, 'no device');
      return res.status(400).json({ error: 'No device registered' });
    }

    const dc = meta.deviceChallenge || {};
    const lastIssuedAt = Number(dc.issuedAt || 0);
    const nowMs = Date.now();
    if (nowMs - lastIssuedAt < CHALLENGE_MIN_INTERVAL_MS) {
      logCtx(ctx, 'throttled', { sinceMs: nowMs - lastIssuedAt });
      return res.status(429).json({ error: 'Too many challenges; slow down' });
    }

    const challengeId = crypto.randomBytes(16).toString('hex');
    const nonce = crypto.randomBytes(32);
    const nonceText = bufferToB64url(nonce); // what we send to client
    const nonceHash = bufferToB64url(crypto.createHash('sha256').update(nonce).digest()); // what we store
    const expSec = Math.floor(nowMs / 1000) + CHALLENGE_TTL_SEC;

    await metaRef.set({
      deviceChallenge: {
        jti: challengeId,
        nonceHash, // store hash of BYTES, not text
        exp: expSec,
        issuedAt: nowMs,
        usedAt: null,
      }
    }, { merge: true });

    logCtx(ctx, 'challenge ok', { challengeId: prefix(challengeId), exp: CHALLENGE_TTL_SEC, nonceB64Prefix: prefix(nonceText) });
    return res.status(200).json({
      challengeId,
      nonce: nonceText,
      aud: AUDIENCE,
      exp: CHALLENGE_TTL_SEC,
    });
  } catch (e) {
    console.error('❌ /devices/challenge failed', e);
    return res.status(500).json({ error: 'Failed to create challenge' });
  }
});

// POST /devices/prove { jws } – compact JWS with ES256 over claims
devicesRouter.post('/prove', async (req, res) => {
  const uid = (req as any).uid as string;
  const ctx = { uid, rid: rid(), step: 'prove' };

  const jws = String(req.body?.jws || '');
  if (!jws) return res.status(400).json({ error: 'Missing jws' });

  try {
    const metaRef = db.collection('user_metadata').doc(uid);
    const snap = await metaRef.get();
    const meta = (snap.data() || {}) as any;

    if ((meta.accountType || '') !== 'member') {
      logCtx(ctx, 'non-member');
      return res.status(403).json({ error: 'Only members can prove device' });
    }
    const allowed = meta.allowedDevice;
    if (!allowed || !allowed.publicKeyJwk || !allowed.deviceId) {
      logCtx(ctx, 'no device');
      return res.status(400).json({ error: 'No device registered' });
    }

    const chal = meta.deviceChallenge || {};
    if (!chal.jti || !chal.nonceHash || !chal.exp) {
      logCtx(ctx, 'no outstanding challenge');
      return res.status(400).json({ error: 'No outstanding challenge' });
    }
    if (chal.usedAt) {
      logCtx(ctx, 'challenge already used', { usedAt: chal.usedAt });
      return res.status(400).json({ error: 'Challenge already used' });
    }
    if (Math.floor(Date.now() / 1000) > Number(chal.exp)) {
      logCtx(ctx, 'challenge expired', { exp: chal.exp });
      return res.status(400).json({ error: 'Challenge expired' });
    }

    const parts = jws.split('.');
    if (parts.length !== 3) return res.status(400).json({ error: 'Invalid JWS' });
    const [hB64, pB64, sB64] = parts;

    let header: any, payload: any;
    try {
      header = JSON.parse(b64urlToBuffer(hB64).toString('utf8'));
      payload = JSON.parse(b64urlToBuffer(pB64).toString('utf8'));
    } catch {
      logCtx(ctx, 'malformed header/payload');
      return res.status(400).json({ error: 'Malformed header/payload' });
    }
    if (header.alg !== 'ES256') return res.status(400).json({ error: 'Unsupported alg' });

    const deviceId = String(payload?.sub || '');
    if (deviceId !== allowed.deviceId) {
      logCtx(ctx, 'device mismatch', { provided: prefix(deviceId), expected: prefix(allowed.deviceId) });
      return res.status(400).json({ error: 'Device mismatch' });
    }
    if (payload?.aud !== AUDIENCE) {
      logCtx(ctx, 'bad audience', { aud: payload?.aud });
      return res.status(400).json({ error: 'Bad audience' });
    }
    if (payload?.jti !== chal.jti) {
      logCtx(ctx, 'jti mismatch', { provided: prefix(payload?.jti), expected: prefix(chal.jti) });
      return res.status(400).json({ error: 'ChallengeId mismatch' });
    }

    const now = Math.floor(Date.now() / 1000);
    if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number' || payload.exp < now) {
      logCtx(ctx, 'token expired/invalid', { iat: payload.iat, exp: payload.exp, now });
      return res.status(400).json({ error: 'Token expired/invalid' });
    }

    // ✅ CRITICAL FIX: hash the BYTES of the nonce, not its base64url string
    try {
      const nonceBytes = b64urlToBuffer(String(payload?.nonce || ''));
      const computedHash = bufferToB64url(crypto.createHash('sha256').update(nonceBytes).digest());
      const match = safeEq(Buffer.from(computedHash), Buffer.from(String(chal.nonceHash)));
      if (!match) {
        logCtx(ctx, 'nonce mismatch', { providedNoncePrefix: prefix(String(payload?.nonce || '')), storedNonceHashPrefix: prefix(chal.nonceHash), computedHashPrefix: prefix(computedHash) });
        return res.status(400).json({ error: 'Nonce mismatch' });
      }
    } catch {
      logCtx(ctx, 'nonce decoding failed');
      return res.status(400).json({ error: 'Nonce malformed' });
    }

    if (header.kid && header.kid !== deviceId) {
      logCtx(ctx, 'kid mismatch', { kid: header.kid, deviceId: prefix(deviceId) });
      return res.status(400).json({ error: 'kid mismatch' });
    }

    const verifyInput = Buffer.from(`${hB64}.${pB64}`, 'utf8');
    const sigDer = coerceToDer(sB64);
    let key: crypto.KeyObject;
    try { key = jwkToPublicKey(allowed.publicKeyJwk); }
    catch { return res.status(400).json({ error: 'Stored JWK invalid' }); }

    const ok = crypto.verify('sha256', verifyInput, key, sigDer);
    if (!ok) { logCtx(ctx, 'signature invalid'); return res.status(400).json({ error: 'Signature invalid' }); }

    await metaRef.set({
      allowedDevice: { ...allowed, lastSeenAt: Date.now(), verifiedAt: Date.now() },
      deviceChallenge: { ...chal, usedAt: Date.now() }, // mark consumed
    }, { merge: true });

    logCtx(ctx, 'prove ok', { deviceId: prefix(deviceId) });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ /devices/prove failed', e);
    return res.status(500).json({ error: 'Device proof failed' });
  }
});

// POST /devices/push-token { pushToken }
devicesRouter.post('/push-token', async (req, res) => {
  const uid = (req as any).uid as string;
  const ctx = { uid, rid: rid(), step: 'push-token' };
  const pushToken = String(req.body?.pushToken || '').trim();
  if (!pushToken) return res.status(400).json({ error: 'Missing pushToken' });
  try {
    const ref = db.collection('user_metadata').doc(uid);
    const snap = await ref.get();
    const meta = (snap.data() || {}) as any;
    const allowed = meta.allowedDevice;
    if (!allowed) { logCtx(ctx, 'no device'); return res.status(400).json({ error: 'No device registered' }); }
    await ref.set({ allowedDevice: { ...allowed, pushToken } }, { merge: true });
    logCtx(ctx, 'push token updated', { hasPush: true });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ /devices/push-token failed', e);
    return res.status(500).json({ error: 'Failed to update push token' });
  }
});

// POST /devices/unpair { memberId }
devicesRouter.post('/unpair', async (req, res) => {
  const actorUid = (req as any).uid as string;
  const ctx = { actorUid, rid: rid(), step: 'unpair' };
  const memberId = String(req.body?.memberId || '').trim();
  if (!memberId) return res.status(400).json({ error: 'Missing memberId' });

  try {
    const groupsSnap = await db.collection('groups').get();
    let authorized = false;
    for (const g of groupsSnap.docs) {
      const adminDoc = await g.ref.collection('members').doc(actorUid).get();
      const role = adminDoc.data()?.role;
      if (adminDoc.exists && ['super-admin', 'admin', 'team-lead'].includes(role)) {
        const memberDoc = await g.ref.collection('members').doc(memberId).get();
        if (memberDoc.exists) { authorized = true; break; }
      }
    }
    if (!authorized) { logCtx(ctx, 'insufficient permissions'); return res.status(403).json({ error: 'Insufficient permissions' }); }

    // Clear user doc and reverse index
    const userMetaRef = db.collection('user_metadata').doc(memberId);
    const userMeta = (await userMetaRef.get()).data() as any;
    const deviceId = userMeta?.allowedDevice?.deviceId as string | undefined;
    await userMetaRef.set({ allowedDevice: null, deviceChallenge: null }, { merge: true });
    if (deviceId) {
      await db.collection('device_index').doc(deviceId).set({ status: 'unpaired', uid: null, loginChallenge: null }, { merge: true });
    }
    logCtx(ctx, 'unpair ok', { memberId: prefix(memberId) });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ /devices/unpair failed', e);
    return res.status(500).json({ error: 'Failed to unpair device' });
  }
});

// GET /devices/me
devicesRouter.get('/me', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const meta = await db.collection('user_metadata').doc(uid).get();
    const allowed = (meta.data() as any)?.allowedDevice || null;
    if (!allowed) return res.status(200).json({ allowedDevice: null });
    const { publicKeyJwk, ...rest } = allowed; // hide raw key in this view (optional)
    return res.status(200).json({ allowedDevice: { ...rest } });
  } catch (e) {
    console.error('❌ /devices/me failed', e);
    return res.status(500).json({ error: 'Failed to load device' });
  }
});
