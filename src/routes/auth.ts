import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../firebase';
import crypto from 'crypto';
import { sendEmail } from '../utils/email';

export const authRouter = express.Router();

authRouter.post('/signup', async (req, res) => {
  const { email, password, groupCodes } = req.body;
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
      email,
      passwordHash: hash,
    });

    const initialGroupCodes: string[] = Array.isArray(groupCodes)
      ? groupCodes.filter((c: any) => typeof c === 'string' && c.trim().length > 0)
      : (typeof groupCodes === 'string' && groupCodes.trim().length > 0
          ? [groupCodes.trim()]
          : []);

    await db.collection('user_metadata').doc(userId).set({
      verificationStatus: 'awaiting',
      onboarded: false,
      groupCodes: initialGroupCodes,
    });

    const token = jwt.sign({ uid: userId }, process.env.JWT_SECRET!, { expiresIn: '7d' });
    return res.status(200).json({ token });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Failed to create user' });
  }
});

authRouter.post('/login', async (req, res) => {
  const email = req.body.email?.toLowerCase()?.trim();
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
    console.log(`[LOGIN] Comparing password: ${password} → match=${isMatch}`);

    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ uid: userDoc.id }, process.env.JWT_SECRET!, { expiresIn: '7d' });
    return res.status(200).json({ token });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// Request password reset: generate token, store, send email
authRouter.post('/forgot-password', async (req, res) => {
  const email = req.body.email?.toLowerCase()?.trim();
  if (!email) return res.status(400).json({ error: 'Missing email' });

  try {
    const snapshot = await db.collection('users').where('email', '==', email).get();
    if (snapshot.empty) {
      // Don't reveal existence
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

// Complete password reset: validate token and set new password
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

// Simple web fallback page to reset password if the app isn't installed
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
