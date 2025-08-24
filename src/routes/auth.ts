import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../firebase';
import crypto from 'crypto';
import { sendEmail } from '../utils/email';
// Use authenticator for Base‑32 secrets + keyuri; we can still import totp if you
// want timeRemaining(), but verification must use authenticator to match Base‑32.
import { authenticator, totp } from 'otplib';
import { verifyJwt } from '../verifyJwt';

export const authRouter = express.Router();

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

// --------- AUTH: SIGNUP ---------
authRouter.post('/signup', async (req, res) => {
  const rawEmail = req.body?.email;
  const password = req.body?.password;
  const groupCodes = req.body?.groupCodes;
  const accountType = req.body?.accountType;

  const email = toEmail(rawEmail);
  if (!email || !password) {
    return res.status(400).json({ error: 'Missing fields' });
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

    const initialGroupCodes: string[] = Array.isArray(groupCodes)
      ? groupCodes.filter((c: any) => typeof c === 'string' && c.trim().length > 0)
      : (typeof groupCodes === 'string' && groupCodes.trim().length > 0
        ? [groupCodes.trim()]
        : []);

    const normalizedType =
      typeof accountType === 'string'
        ? String(accountType).toLowerCase()
        : 'individual';

    const isGroupAdminSignup = normalizedType === 'carer' || normalizedType === 'organization';

    await db.collection('user_metadata').doc(userId).set({
      verificationStatus: 'awaiting',
      onboarded: false,
      groupCodes: initialGroupCodes,
      accountType: normalizedType,
    });

    if (isGroupAdminSignup) {
      const groupRef = db.collection('groups').doc();
      const groupId = groupRef.id;
      const inferredName = normalizedType === 'organization'
        ? email.split('@')[1]?.split('.')?.[0] || 'Organization'
        : email.split('@')[0] || 'Carer';

      await groupRef.set({
        name: inferredName,
        type: normalizedType, // 'carer' | 'organization'
        createdBy: userId,
        createdAt: Date.now(),
        tier: 'trial',
        trialEndsAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 1 week trial
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
      }, { merge: true });
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
      return res.status(401).json({ error: 'Invalid credentials' });
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
      return res.status(401).json({ error: 'Invalid credentials' });
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
    const expiresAt = Date.now() + 1000 * 60 * 30; // 30 minutes

    await db.collection('password_resets').doc(userDoc.id).set({
      token,
      expiresAt,
    });

    const appDeepLink = `howdy://reset-password?token=${token}&uid=${userDoc.id}`;
    const backendBase = process.env.BACKEND_BASE_URL || 'http://localhost:5000';
    const webFallback = `${backendBase}/auth/reset-password?token=${token}&uid=${userDoc.id}`;
    await sendEmail(
      email,
      'Reset your Howdy password',
      `Open the app to reset your password: ${appDeepLink}\n\nIf the app does not open, use this web link: ${webFallback}`,
      `<p><strong>Reset via the app (preferred):</strong></p>
       <p><a href="${appDeepLink}">${appDeepLink}</a></p>
       <p style="margin-top:16px"><strong>Or reset on the web:</strong></p>
       <p><a href="${webFallback}">${webFallback}</a></p>`
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

  try {
    const resetDoc = await db.collection('password_resets').doc(uid).get();
    const data = resetDoc.data();
    if (!data || data.token !== token || typeof data.expiresAt !== 'number' || Date.now() > data.expiresAt) {
      return res.status(400).json({ error: 'Invalid or expired reset link' });
    }

    const hash = await bcrypt.hash(password, 10);
    await db.collection('users').doc(uid).update({ passwordHash: hash });
    await db.collection('password_resets').doc(uid).delete();

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
        button { width:100%; margin-top:16px; padding:12px; border:0; border-radius:10px; background:#1a73e8; color:#fff; font-weight:600; }
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
        <label>Confirm password</label>
        <input id="p2" type="password" />
        <button id="submit">Reset password</button>
        <div id="msg" class="msg"></div>
      </div>
      <script>
        const el = (id) => document.getElementById(id);
        el('submit').addEventListener('click', async () => {
          const p1 = el('p1').value.trim();
          const p2 = el('p2').value.trim();
          const msg = el('msg');
          msg.textContent = '';
          msg.className = 'msg';
          if (!p1 || p1 !== p2) {
            msg.textContent = 'Passwords do not match';
            msg.classList.add('err');
            return;
          }
          try {
            const r = await fetch('/auth/reset-password', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
              body: JSON.stringify({ uid: '${uid}', token: '${token}', password: p1 })
            });
            if (r.ok) {
              msg.textContent = 'Password updated. You can now sign in in the app.';
              msg.classList.add('ok');
            } else {
              const data = await r.json().catch(() => ({}));
              msg.textContent = data.error || 'Reset failed';
              msg.classList.add('err');
            }
          } catch (e) {
            msg.textContent = 'Network error';
            msg.classList.add('err');
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
