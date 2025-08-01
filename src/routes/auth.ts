import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { db } from '../firebase';

export const authRouter = express.Router();

authRouter.post('/signup', async (req, res) => {
  const { email, password } = req.body;
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

    await db.collection('user_metadata').doc(userId).set({
      verificationStatus: 'awaiting',
      onboarded: false,
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
