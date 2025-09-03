import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { FieldValue } from 'firebase-admin/firestore';
import { sendEmail } from '../utils/email';
import { authenticator, totp } from 'otplib';
import { verifyJwt } from '../verifyJwt';
import { db } from '../firebase';

export const authRouter = express.Router();

// /**
//  * Resolve a group by a human-entered group code.
//  * Supports two storage styles:
//  *  1) groups.groupCode === CODE
//  *  2) groups/*/codes/<doc> with { code: CODE, active?: boolean }


async function resolveGroupByCode(input: string): Promise<{
  groupId: string;
  groupName: string;
  code: string;
} | null> {
  const code = String(input || '').trim().toUpperCase();
  if (!code) return null;

  // Try groups.groupCode == code
  const byRoot = await db.collection('groups').where('groupCode', '==', code).limit(1).get();
  if (!byRoot.empty) {
    const g = byRoot.docs[0];
    const d = g.data() || {};
    return { groupId: g.id, groupName: String(d.name || ''), code };
  }

  // Try collectionGroup('codes') where code == code
  const cg = await db.collectionGroup('codes').where('code', '==', code).limit(1).get();
  if (!cg.empty) {
    const c = cg.docs[0];
    const active = (c.data() as any)?.active !== false; // default to active if missing
    if (!active) return null;
    const groupRef = c.ref.parent.parent;
    if (!groupRef) return null;
    const g = await groupRef.get();
    const d = g.data() || {};
    return { groupId: g.id, groupName: String(d.name || ''), code };
  }

  return null;
}

// --- Group code validation (public) ---
authRouter.post('/validate-group-code', async (req, res) => {
  try {
    const code = String(req.body?.code || '');
    const found = await resolveGroupByCode(code);
    if (!found) return res.status(404).json({ error: 'Invalid group code' });
    return res.status(200).json({ ok: true, groupId: found.groupId, groupName: found.groupName });
  } catch (e) {
    console.error('❌ validate-group-code error', e);
    return res.status(500).json({ error: 'Failed to validate group code' });
  }
});

// POST /auth/signup-invite { token, password }
authRouter.post('/signup-invite', async (req, res) => {
  const token = String(req.body?.token || '');
  const password = String(req.body?.password || '');
  if (!token || !password) return res.status(400).json({ error: 'Missing fields' });
  try {
    const inviteDoc = await db.collection('group_invites').doc(token).get();
    if (!inviteDoc.exists) return res.status(400).json({ error: 'Invalid token' });
    const inv = inviteDoc.data() as any;
    if (Date.now() > (inv.expiresAt || 0)) return res.status(400).json({ error: 'Invite expired' });

    const email = String(inv.email || '').toLowerCase();
    if (!email) return res.status(400).json({ error: 'Invite missing email' });

    const pwErr = validatePasswordComplexity(password);
    if (pwErr) return res.status(400).json({ error: pwErr });

    // create user if not exists
    const existing = await db.collection('users').where('email', '==', email).get();
    if (!existing.empty) return res.status(400).json({ error: 'Account already exists for this email' });

    const hash = await bcrypt.hash(password, 10);
    const userRef = db.collection('users').doc();
    const uid = userRef.id;
    await userRef.set({ email, passwordHash: hash });

    // attach metadata and group code
    const groupSnap = await db.collection('groups').doc(inv.groupId).get();
    const group = groupSnap.data() || {};
    const groupCode = group.groupCode || null;
    const accountType = inv.role === 'member' ? 'member' : 'carer';
    await db.collection('user_metadata').doc(uid).set({
      accountType,
      primaryGroupId: inv.groupId,
      ...(groupCode ? { groupCodes: [groupCode] } : {}),
    }, { merge: true });

    // accept invite: add to group members
    await db.collection('groups').doc(inv.groupId).collection('members').doc(email).set({
      uid,
      email,
      role: inv.role || 'member',
      status: 'active',
      acceptedAt: Date.now(),
    }, { merge: true });
    await inviteDoc.ref.delete();

    return res.status(200).json({ ok: true, uid });
  } catch (e) {
    console.error('❌ signup-invite failed', e);
    return res.status(500).json({ error: 'Failed to sign up' });
  }
});

// POST /auth/accept-member-invite { token }
authRouter.post('/accept-member-invite', async (req, res) => {
  const token = String(req.body?.token || '');
  if (!token) return res.status(400).json({ error: 'Missing token' });
  try {
    const inviteDoc = await db.collection('group_invites').doc(token).get();
    if (!inviteDoc.exists) return res.status(400).json({ error: 'Invalid token' });
    const inv = inviteDoc.data() as any;
    if (Date.now() > (inv.expiresAt || 0)) return res.status(400).json({ error: 'Invite expired' });
    const email = String(inv.email || '').toLowerCase();
    if (!email) return res.status(400).json({ error: 'Invite missing email' });

    // create user if not exists; mark isMember
    let uid: string | null = null;
    const existing = await db.collection('users').where('email', '==', email).get();
    if (!existing.empty) {
      uid = existing.docs[0].id;
    } else {
      const userRef = db.collection('users').doc();
      uid = userRef.id;
      await userRef.set({ email, isMember: true });
    }

    await db.collection('users').doc(uid!).set({ isMember: true }, { merge: true });
    const groupSnap = await db.collection('groups').doc(inv.groupId).get();
    const group = groupSnap.data() || {};
    const groupCode = group.groupCode || null;
    await db.collection('user_metadata').doc(uid!).set({
      accountType: 'member',
      primaryGroupId: inv.groupId,
      ...(groupCode ? { groupCodes: [groupCode] } : {}),
    }, { merge: true });

    await db.collection('groups').doc(inv.groupId).collection('members').doc(email).set({
      uid,
      email,
      role: 'member',
      status: 'active',
      acceptedAt: Date.now(),
    }, { merge: true });
    await inviteDoc.ref.delete();

    const accessToken = jwt.sign({ uid }, process.env.JWT_SECRET!, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ uid, t: 'refresh' }, process.env.JWT_SECRET!, { expiresIn: '180d' });
    await db.collection('refresh_tokens').doc().set({ uid, token: refreshToken, createdAt: Date.now() });

    return res.status(200).json({ ok: true, uid, accessToken, refreshToken });
  } catch (e) {
    console.error('❌ accept-member-invite failed', e);
    return res.status(500).json({ error: 'Failed to accept invite' });
  }
});

// --------- Config knobs ---------
const TOTP_WINDOW_STEPS = Number(process.env.TOTP_WINDOW_STEPS || '1'); // bump to 2–3 temporarily if diagnosing drift
const MFA_TMP_TTL_MS = Number(process.env.MFA_TMP_TTL_MS || (10 * 60 * 1000)); // reuse setup secret for 10 minutes
const ENABLE_MFA_DEBUG = process.env.ENABLE_MFA_DEBUG === 'true';

// --------- Helpers ---------
const toEmail = (v: any) => String(v || '').trim().toLowerCase();
const nowIso = () => new Date().toISOString();
const fp = (s?: string) =>
  s ? crypto.createHash('sha256').update(s).digest('hex').slice(0, 8) : 'null';

/**
 * Verify a TOTP code for a Base‑32 secret using `authenticator`.
 * We set `authenticator.options.window` temporarily (no TS issues) and restore it.
 */
function verifyTotpBase32WithWindow(secretBase32: string, token: string, windowSteps: number): boolean {
  const a: any = authenticator;
  const prev = { ...(a.options || {}) };
  a.options = { ...prev, window: windowSteps };
  try {
    return authenticator.verify({ token, secret: secretBase32 });
  } finally {
    a.options = prev;
  }
}

/**
 * Validate password complexity.
 * Rules: 8–128 chars, no spaces, at least 1 upper, 1 lower, 1 digit, 1 special.
 */
function validatePasswordComplexity(password: unknown): string | null {
  const p = typeof password === 'string' ? password : '';
  if (!p) return 'Missing password';
  if (p.length < 8 || p.length > 128) return 'Password must be 8–128 characters';
  if (/\s/.test(p)) return 'Password cannot contain spaces';
  if (!/[A-Z]/.test(p)) return 'Password must include an uppercase letter';
  if (!/[a-z]/.test(p)) return 'Password must include a lowercase letter';
  if (!/[0-9]/.test(p)) return 'Password must include a number';
  if (!/[!@#$%^&*()\-_=+\[\]{};:'",.<>\/?`~|\\]/.test(p)) return 'Password must include a special character';
  return null;
}

// --------- AUTH: SIGNUP ---------
authRouter.post('/signup', async (req, res) => {
  const rawEmail = req.body?.email;
  const password = req.body?.password;
  const groupCodes = req.body?.groupCodes; // legacy array
  const groupCodeSingle = req.body?.groupCode; // new single string
  const accountType = req.body?.accountType;
  const groupNameInput = typeof req.body?.groupName === 'string' ? String(req.body.groupName).trim() : '';

  const email = toEmail(rawEmail);
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const pwErr = validatePasswordComplexity(password);
  if (pwErr) {
    return res.status(400).json({ error: pwErr });
  }

  try {
    const userQuery = await db.collection('users').where('email', '==', email).get();
    if (!userQuery.empty) {
      return res.status(400).json({ error: 'Email already exists' });
    }

    const hash = await bcrypt.hash(password, 10);
    const userRef = db.collection('users').doc();
    const userId = userRef.id;

    await userRef.set({
      email,               // store lowercase email to match login queries
      passwordHash: hash,
    });

    // Normalize account type
    const normalizedType =
      typeof accountType === 'string'
        ? String(accountType).toLowerCase()
        : 'individual';

    // Normalize incoming group code
    const incomingCode: string | null =
      typeof groupCodeSingle === 'string' && groupCodeSingle.trim().length > 0
        ? groupCodeSingle.trim().toUpperCase()
        : (Array.isArray(groupCodes) && groupCodes.length > 0 && typeof groupCodes[0] === 'string'
            ? String(groupCodes[0]).trim().toUpperCase()
            : null);

    // Base metadata
    await db.collection('user_metadata').doc(userId).set({
      verificationStatus: 'awaiting',
      onboarded: false,
      accountType: normalizedType,
      ...(incomingCode ? { groupCodes: [incomingCode] } : {}),
    }, { merge: true });

    if (normalizedType === 'organization') {
      // NEW: Must join an existing org via required groupCode
      if (!incomingCode) {
        return res.status(400).json({ error: 'Group Code is required for organization accounts' });
      }
      const found = await resolveGroupByCode(incomingCode);
      if (!found) {
        return res.status(400).json({ error: 'Invalid or inactive Group Code' });
      }

      const groupId = found.groupId;

      // Attach user to the existing org (role can be tuned; using 'admin' by default)
      await db.collection('groups').doc(groupId).collection('members').doc(userId).set({
        uid: userId,
        email,
        role: 'admin',
        addedAt: Date.now(),
        status: 'active',
      }, { merge: true });

      await db.collection('user_metadata').doc(userId).set({
        primaryGroupId: groupId,
      }, { merge: true });
    } else if (normalizedType === 'carer') {
      // Carer creates a fresh group with explicit group name from signup
      if (!groupNameInput) {
        return res.status(400).json({ error: 'Group name is required for carer accounts' });
      }
      const groupRef = db.collection('groups').doc();
      const groupId = groupRef.id;
      const providedName = groupNameInput;

      const groupCode = crypto.randomBytes(3).toString('hex').toUpperCase();
      await groupRef.set({
        name: providedName,
        type: normalizedType, // 'carer'
        createdBy: userId,
        createdAt: Date.now(),
        tier: 'trial',
        trialEndsAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 1 week trial
        groupCode,
      });

      await groupRef.collection('members').doc(userId).set({
        uid: userId,
        email,
        role: 'super-admin',
        addedAt: Date.now(),
        status: 'active',
      });

      await db.collection('user_metadata').doc(userId).set({
        primaryGroupId: groupId,
        groupCodes: [groupCode],
      }, { merge: true });
    } else {
      // 'individual' – nothing extra to do
    }

    const accessToken = jwt.sign({ uid: userId }, process.env.JWT_SECRET!, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ uid: userId, t: 'refresh' }, process.env.JWT_SECRET!, { expiresIn: '180d' });
    await db.collection('refresh_tokens').doc().set({ uid: userId, token: refreshToken, createdAt: Date.now() });
    return res.status(200).json({ accessToken, refreshToken });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Failed to create user' });
  }
});

// --------- AUTH: LOGIN ---------
authRouter.post('/login', async (req, res) => {
  const email = toEmail(req.body.email);
  const password = req.body.password;

  if (!email || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  try {
    const snapshot = await db.collection('users').where('email', '==', email).get();
    if (snapshot.empty) {
      console.log('❌ No user found for email:', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();

    if (!userData.passwordHash) {
      console.log('❌ No passwordHash found for user:', email);
      return res.status(401).json({ error: 'No password saved' });
    }

    const isMatch = await bcrypt.compare(password, userData.passwordHash);
    console.log(`[LOGIN] match=${isMatch} email=${email}`);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const meta = await db.collection('user_metadata').doc(userDoc.id).get();
    const mfa = (meta.data()?.mfa || {}) as any;
    const mfaRequired = !!mfa.required && Array.isArray(mfa.methods) && mfa.methods.length > 0;

    console.log(`[LOGIN] uid=${userDoc.id} mfaRequired=${mfaRequired} methods=${JSON.stringify(mfa.methods || [])}`);

    if (mfaRequired) {
      const mfaToken = jwt.sign({ uid: userDoc.id, t: 'mfa' }, process.env.JWT_SECRET!, { expiresIn: '5m' });
      return res.status(200).json({ mfaRequired: true, methods: mfa.methods, mfaToken });
    }

    const accessToken = jwt.sign({ uid: userDoc.id }, process.env.JWT_SECRET!, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ uid: userDoc.id, t: 'refresh' }, process.env.JWT_SECRET!, { expiresIn: '180d' });
    await db.collection('refresh_tokens').doc().set({ uid: userDoc.id, token: refreshToken, createdAt: Date.now() });
    return res.status(200).json({ accessToken, refreshToken });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// --------- PASSWORD RESET ---------
authRouter.post('/forgot-password', async (req, res) => {
  const email = toEmail(req.body.email);
  if (!email) return res.status(400).json({ error: 'Missing email' });

  try {
    const snapshot = await db.collection('users').where('email', '==', email).get();
    if (snapshot.empty) {
      return res.status(200).json({ ok: true });
    }

    const userDoc = snapshot.docs[0];
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = Date.now() + 6 * 60 * 60 * 1000; // 6 hours

    await db.collection('password_resets').doc(userDoc.id).set({ token, expiresAt });
    await db.collection('password_resets').doc(token).set({ uid: userDoc.id, expiresAt });

    const backendBase = process.env.BACKEND_BASE_URL || 'http://localhost:5000';
    const webUrl = `${backendBase}/auth/reset-password?token=${token}&uid=${userDoc.id}`;
    await sendEmail(
      email,
      'Reset your Howdy password',
      `Click here to reset your password.`,
      `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;font-size:14px;color:#222;line-height:1.5">
        <p>Hi,</p>
        <p>We received a request to reset your Howdy password. Click the button below to continue.</p>
        <p>
          <a href="${webUrl}" style="
            display:inline-block;
            background:#d37f1c;
            color:#fff;
            padding:12px 16px;
            border-radius:8px;
            text-decoration:none;
            font-weight:600;">
            Reset your password
          </a>
        </p>
        <p>This link will expire in 30 minutes. If you didn’t request a password reset, you can safely ignore this email.</p>
        <p>Thanks,<br/>The Howdy Team</p>
      </div>`
    );

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('Forgot password error:', e);
    return res.status(500).json({ error: 'Failed to start reset' });
  }
});

authRouter.post('/reset-password', async (req, res) => {
  const { uid, token, password } = req.body;
  if (!uid || !token || !password) {
    return res.status(400).json({ error: 'Missing fields' });
  }

  const pwErr = validatePasswordComplexity(password);
  if (pwErr) {
    return res.status(400).json({ error: pwErr });
  }

  try {
    // Prefer token-keyed doc for validation to allow multiple outstanding links
    const tokenDoc = await db.collection('password_resets').doc(token).get();
    let valid = false;
    if (tokenDoc.exists) {
      const tdata = tokenDoc.data() as any;
      if (tdata && tdata.uid === uid && typeof tdata.expiresAt === 'number' && Date.now() <= tdata.expiresAt) {
        valid = true;
      }
    } else {
      const resetDoc = await db.collection('password_resets').doc(uid).get();
      const data = resetDoc.data() as any;
      if (data && data.token === token && typeof data.expiresAt === 'number' && Date.now() <= data.expiresAt) {
        valid = true;
      }
    }
    if (!valid) {
      return res.status(400).json({ error: 'Invalid or expired reset link' });
    }

    const hash = await bcrypt.hash(password, 10);
    await db.collection('users').doc(uid).update({ passwordHash: hash });
    // Clean up both potential records
    await db.collection('password_resets').doc(uid).delete().catch(() => {});
    await db.collection('password_resets').doc(token).delete().catch(() => {});

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('Reset password error:', e);
    return res.status(500).json({ error: 'Failed to reset password' });
  }
});

// --------- MFA: SETUP (TOTP) ---------
authRouter.post('/mfa/setup/totp/begin', verifyJwt, async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const user = await db.collection('users').doc(uid).get();
    const email = user.data()?.email || uid;

    // Reuse an existing secret briefly to avoid invalidating the QR if user regenerates
    const tmpRef = db.collection('mfa_tmp').doc(uid);
    const tmp = await tmpRef.get();
    let secret: string | null = null;
    let reused = false;
    let tx: string;

    if (tmp.exists) {
      const { secret: s, createdAt, tx: t } = tmp.data() as any;
      if (s && typeof createdAt === 'number' && (Date.now() - createdAt) < MFA_TMP_TTL_MS) {
        secret = s;
        reused = true;
        tx = t || crypto.randomUUID();
      } else {
        tx = crypto.randomUUID();
      }
    } else {
      tx = crypto.randomUUID();
    }

    if (!secret) {
      secret = authenticator.generateSecret(); // Base‑32
      await tmpRef.set({ secret, createdAt: Date.now(), tx });
    } else {
      await tmpRef.set({ secret, createdAt: Date.now(), tx }, { merge: true });
    }

    const otpauth = authenticator.keyuri(email, 'Howdy', secret); // uses Base‑32

    const step = (authenticator as any).options?.step ?? 30;
    console.log(
      `[MFA TOTP BEGIN] uid=${uid} tx=${tx} time=${nowIso()} reused=${reused} secretFp=${fp(
        secret
      )} step=${step} ttlMs=${MFA_TMP_TTL_MS} otpauthLen=${otpauth.length}`
    );

    // Return secret for manual entry as well
    return res.status(200).json({ otpauth, secret, tx, step });
  } catch (e) {
    console.error('TOTP begin error:', e);
    return res.status(500).json({ error: 'Failed to start TOTP setup' });
  }
});

authRouter.post('/mfa/setup/totp/verify', verifyJwt, async (req, res) => {
  const uid = (req as any).uid as string;
  const code = String(req.body?.code || '').replace(/\s+/g, '');
  const clientTx = String(req.body?.tx || '');
  if (!code) return res.status(400).json({ error: 'Missing code' });

  try {
    const tmpRef = db.collection('mfa_tmp').doc(uid);
    const tmp = await tmpRef.get();
    const { secret, createdAt, tx } = (tmp.data() || {}) as any;
    if (!secret) return res.status(400).json({ error: 'No setup in progress' });

    const step = (authenticator as any).options?.step ?? 30;
    const timeRemaining = typeof (authenticator as any).timeRemaining === 'function'
      ? (authenticator as any).timeRemaining()
      : 'n/a';

    const valid = verifyTotpBase32WithWindow(secret, code, TOTP_WINDOW_STEPS);

    console.log(
      `[MFA TOTP VERIFY] uid=${uid} tx=${tx || 'n/a'} clientTx=${clientTx || 'n/a'} time=${nowIso()} `
      + `codeLen=${code.length} secretFp=${fp(secret)} window=${TOTP_WINDOW_STEPS} step=${step} `
      + `timeRemaining=${timeRemaining} tmpAgeSec=${createdAt ? Math.round((Date.now()-createdAt)/1000) : 'n/a'} `
      + `valid=${valid}`
    );

    if (!valid) return res.status(400).json({ error: 'Invalid code' });

    // Merge MFA methods (don’t clobber existing)
    const metaRef = db.collection('user_metadata').doc(uid);
    const metaSnap = await metaRef.get();
    const prevMfa = (metaSnap.data()?.mfa || {}) as any;
    const prevMethods = Array.isArray(prevMfa.methods) ? prevMfa.methods : [];
    const methods = Array.from(new Set([...(prevMethods as string[]), 'totp']));

    await metaRef.set(
      {
        mfa: {
          ...prevMfa,
          required: true,
          methods,
          totpSecretEnc: secret, // TODO: encrypt in production
        },
      },
      { merge: true }
    );

    await tmpRef.delete();
    console.log(`[MFA TOTP VERIFY] uid=${uid} tx=${tx || 'n/a'} status=ENABLED methods=${JSON.stringify(methods)}`);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('TOTP verify error:', e);
    return res.status(500).json({ error: 'Failed to verify TOTP' });
  }
});

// --------- MFA: CHALLENGE (email only for now) ---------
authRouter.post('/mfa/challenge', async (req, res) => {
  let uid: string | null = (req as any).uid || null;
  const method = String(req.body?.method || '');
  const mfaToken = req.body?.mfaToken ? String(req.body.mfaToken) : '';
  if (!uid && mfaToken) {
    try {
      const payload = jwt.verify(mfaToken, process.env.JWT_SECRET!) as any;
      if (payload && payload.t === 'mfa' && payload.uid) uid = String(payload.uid);
    } catch (_) {}
  }
  if (!uid) return res.status(401).json({ error: 'Unauthorized' });
  if (!['email'].includes(method)) return res.status(400).json({ error: 'Unsupported method' });

  try {
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await db.collection('mfa_email_codes').doc(uid).set(
      { code, createdAt: Date.now() },
      { merge: true }
    );
    const user = await db.collection('users').doc(uid).get();
    const email = user.data()?.email;
    console.log(`[MFA EMAIL CHALLENGE] uid=${uid} sent=${!!email}`);
    if (email) {
      await sendEmail(
        email,
        'Your Howdy login code',
        `Your code is: ${code}`,
        `<p>Your code: <strong>${code}</strong></p>`
      );
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('MFA challenge error:', e);
    return res.status(500).json({ error: 'Failed to send code' });
  }
});

// --------- MFA: VERIFY (TOTP or Email after login) ---------
authRouter.post('/mfa/verify', async (req, res) => {
  const mfaToken = String(req.body?.mfaToken || '');
  const method = String(req.body?.method || '');
  const code = String(req.body?.code || '');
  if (!mfaToken || !method) return res.status(400).json({ error: 'Missing fields' });

  try {
    const payload = jwt.verify(mfaToken, process.env.JWT_SECRET!) as any;
    if (!payload || payload.t !== 'mfa' || !payload.uid) {
      return res.status(401).json({ error: 'Invalid mfa token' });
    }
    const uid = payload.uid as string;

    const meta = await db.collection('user_metadata').doc(uid).get();
    const mfa = (meta.data()?.mfa || {}) as any;
    if (!Array.isArray(mfa.methods) || mfa.methods.length === 0) {
      return res.status(400).json({ error: 'MFA not configured' });
    }

    let ok = false;
    if (method === 'totp' && typeof mfa.totpSecretEnc === 'string' && mfa.totpSecretEnc) {
      const step = (authenticator as any).options?.step ?? 30;
      const timeRemaining = typeof (authenticator as any).timeRemaining === 'function'
        ? (authenticator as any).timeRemaining()
        : 'n/a';

      ok = verifyTotpBase32WithWindow(mfa.totpSecretEnc, code.replace(/\s+/g, ''), TOTP_WINDOW_STEPS);

      console.log(
        `[MFA VERIFY] method=totp uid=${uid} time=${nowIso()} codeLen=${code.length} `
        + `secretFp=${fp(mfa.totpSecretEnc)} window=${TOTP_WINDOW_STEPS} step=${step} timeRemaining=${timeRemaining} ok=${ok}`
      );
    } else if (method === 'email') {
      const doc = await db.collection('mfa_email_codes').doc(uid).get();
      if (doc.exists) {
        const { code: stored, createdAt } = (doc.data() || {}) as any;
        ok = stored === code && Date.now() - (createdAt || 0) < 5 * 60_000;
      }
      console.log(`[MFA VERIFY] method=email uid=${uid} ok=${ok}`);
    }
    if (!ok) return res.status(400).json({ error: 'Invalid code' });

    const accessToken = jwt.sign({ uid }, process.env.JWT_SECRET!, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ uid, t: 'refresh' }, process.env.JWT_SECRET!, { expiresIn: '180d' });
    await db.collection('refresh_tokens').doc().set({ uid, token: refreshToken, createdAt: Date.now() });
    return res.status(200).json({ accessToken, refreshToken });
  } catch (e) {
    console.error('MFA verification error:', e);
    return res.status(401).json({ error: 'MFA verification failed' });
  }
});

// --------- Refresh access token ---------
authRouter.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body || {};
  if (!refreshToken) return res.status(400).json({ error: 'Missing refreshToken' });
  try {
    const snap = await db.collection('refresh_tokens').where('token', '==', refreshToken).limit(1).get();
    if (snap.empty) return res.status(401).json({ error: 'Invalid refresh token' });
    const payload = jwt.verify(refreshToken, process.env.JWT_SECRET!) as any;
    if (!payload || payload.t !== 'refresh' || !payload.uid) {
      return res.status(401).json({ error: 'Invalid refresh token' });
    }
    const newAccess = jwt.sign({ uid: payload.uid }, process.env.JWT_SECRET!, { expiresIn: '15m' });
    return res.status(200).json({ accessToken: newAccess });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid refresh token' });
  }
});

// --------- Simple web fallback page to reset password ---------
authRouter.get('/reset-password', async (req, res) => {
  const token = (req.query.token as string) || '';
  const uid = (req.query.uid as string) || '';
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Reset password • Howdy</title>
      <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Inter, sans-serif; background:#f7f7f8; padding:24px; }
        .card { max-width:480px; margin: 40px auto; background:#fff; border:1px solid #e6e6eb; border-radius:12px; padding:20px; }
        label { display:block; margin:12px 0 6px; font-weight:600; }
        input { width:100%; padding:10px; border:1px solid #c9c9cf; border-radius:8px; }
        button { width:100%; margin-top:16px; padding:12px; border:0; border-radius:10px; background:#d37f1c; color:#fff; font-weight:600; cursor:pointer; transition: background-color .15s ease, opacity .15s ease; }
        button:hover:not(:disabled) { background:#b86f18; }
        button:disabled { opacity:.6; cursor:not-allowed; }
        .msg { margin-top:12px; }
        .err { color:#c62828; }
        .ok { color:#2e7d32; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Reset your password</h2>
        <p>Enter a new password for your account.</p>
        <label>New password</label>
        <input id="p1" type="password" />
        <button id="toggleP1" type="button" style="
          width:auto; margin-top:6px; padding:4px 0; background:transparent; border:0; color:#555; text-decoration:underline; cursor:pointer;
        ">Show password</button>
        <label>Confirm password</label>
        <input id="p2" type="password" />
        <button id="toggleP2" type="button" style="
          width:auto; margin-top:6px; padding:4px 0; background:transparent; border:0; color:#555; text-decoration:underline; cursor:pointer;
        ">Show password</button>
        <button id="submit">Reset password</button>
        <div id="msg" class="msg"></div>
        <div id="pwChecks" style="font-size:13px; margin-top:8px">
          <div id="pwLen"><span class="sym">•</span> 8–128 characters</div>
          <div id="pwSpace"><span class="sym">•</span> No spaces</div>
          <div id="pwUpper"><span class="sym">•</span> Uppercase letter</div>
          <div id="pwLower"><span class="sym">•</span> Lowercase letter</div>
          <div id="pwDigit"><span class="sym">•</span> Number</div>
          <div id="pwSpecial"><span class="sym">•</span> Special character</div>
          <div id="pwMatch"><span class="sym">•</span> Passwords match</div>
        </div>
      </div>
      <script>
        const el = (id) => document.getElementById(id);
        const setReq = (id, ok) => {
          const node = el(id);
          const sym = node.querySelector('.sym');
          if (sym) sym.textContent = ok ? '✓' : '•';
          node.style.color = ok ? '#2e7d32' : '#222';
          node.style.fontWeight = ok ? '600' : '400';
        };
        const requirements = () => {
          const p1 = el('p1').value;
          const p2 = el('p2').value;
          const lenOk = p1.length >= 8 && p1.length <= 128;
          const noSpace = !/\\s/.test(p1);
          const upper = /[A-Z]/.test(p1);
          const lower = /[a-z]/.test(p1);
          const digit = /[0-9]/.test(p1);
          const special = /[^A-Za-z0-9\\s]/.test(p1);
          const match = p1.length > 0 && p1 === p2;
          return { lenOk, noSpace, upper, lower, digit, special, match };
        };
        const submitBtn = el('submit');
        const updateChecklist = () => {
          const r = requirements();
          setReq('pwLen', r.lenOk);
          setReq('pwSpace', r.noSpace);
          setReq('pwUpper', r.upper);
          setReq('pwLower', r.lower);
          setReq('pwDigit', r.digit);
          setReq('pwSpecial', r.special);
          setReq('pwMatch', r.match);
          submitBtn.disabled = !(r.lenOk && r.noSpace && r.upper && r.lower && r.digit && r.special && r.match);
        };
        ['p1','p2'].forEach(id => el(id).addEventListener('input', updateChecklist));
        const setupToggle = (inputId, btnId) => {
          const inp = el(inputId);
          const btn = el(btnId);
          btn.addEventListener('click', () => {
            const isPwd = inp.getAttribute('type') === 'password';
            inp.setAttribute('type', isPwd ? 'text' : 'password');
            btn.textContent = isPwd ? 'Hide password' : 'Show password';
          });
        };
        setupToggle('p1','toggleP1');
        setupToggle('p2','toggleP2');
        updateChecklist();
        submitBtn.addEventListener('click', async () => {
          const p1 = el('p1').value.trim();
          const p2 = el('p2').value.trim();
          const msg = el('msg');
          msg.textContent = '';
          msg.className = 'msg';
          // Final guard on the client (server also validates)
          const r = requirements();
          if (!(r.lenOk && r.noSpace && r.upper && r.lower && r.digit && r.special && r.match)) {
            msg.textContent = 'Please meet all password requirements';
            msg.classList.add('err');
            return;
          }
          submitBtn.disabled = true;
          const prevText = submitBtn.textContent;
          submitBtn.textContent = 'Resetting…';
          try {
            const r = await fetch('/auth/reset-password', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
              body: JSON.stringify({ uid: '${uid}', token: '${token}', password: p1 })
            });
            if (r.ok) {
              msg.textContent = 'Password updated. You can now sign into the app.';
              msg.classList.add('ok');
              submitBtn.textContent = 'Password updated';
              submitBtn.disabled = true; // keep disabled after success
            } else {
              const data = await r.json().catch(() => ({}));
              msg.textContent = data.error || 'Reset failed';
              msg.classList.add('err');
              submitBtn.textContent = prevText;
              submitBtn.disabled = false; // allow retry on error
            }
          } catch (e) {
            msg.textContent = 'Network error';
            msg.classList.add('err');
            submitBtn.textContent = prevText;
            submitBtn.disabled = false;
          }
        });
      </script>
    </body>
  </html>`);
});

// --------- OPTIONAL: Debug endpoint (enable only during development) ---------
if (ENABLE_MFA_DEBUG) {
  authRouter.post('/mfa/debug/peek', verifyJwt, async (req, res) => {
    const uid = (req as any).uid as string;
    const tmp = await db.collection('mfa_tmp').doc(uid).get();
    const secret = tmp.data()?.secret;
    if (!secret) return res.status(400).json({ error: 'no secret' });
    const now = authenticator.generate(secret); // Base‑32 generate for parity
    const timeRemaining = typeof (authenticator as any).timeRemaining === 'function'
      ? (authenticator as any).timeRemaining()
      : 'n/a';
    return res.json({ serverTime: new Date().toISOString(), now, timeRemaining });
  });
}
