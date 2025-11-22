import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { auth as firebaseAuth } from './firebase';

export async function verifyJwt(req: Request, res: Response, next: NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing token' });
  }

  try {
    const token = authHeader.split(' ')[1];
    // First try backend-signed JWT (HS256)
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any;
      if (decoded && decoded.uid) {
        (req as any).uid = decoded.uid;
        return next();
      }
    } catch (_) {
      // fall through to Firebase verification
    }

    // Fallback: accept Firebase ID tokens issued by our project
    try {
      const fb = await firebaseAuth.verifyIdToken(token);
      if (fb && fb.uid) {
        (req as any).uid = fb.uid;
        return next();
      }
    } catch (_) {
      // ignore
    }

    return res.status(401).json({ error: 'Invalid or expired token' });
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
