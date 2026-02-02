import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { db, auth as firebaseAuth } from './firebase';

const sessionCache = new Map<string, { sid: string; expires: number }>();
const CACHE_TTL = 60_000; // Cache session ID for 60 seconds to reduce DB hits

export function clearSessionCache(uid: string) {
  sessionCache.delete(uid);
}

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
        // Single session enforcement: Check if sid matches currentSessionId in metadata
        if (decoded.sid) {
          const now = Date.now();
          const cached = sessionCache.get(decoded.uid);
          let currentSid: string | undefined;

          if (cached && cached.expires > now) {
            currentSid = cached.sid;
          } else {
            const meta = await db.collection('user_metadata').doc(decoded.uid).get();
            currentSid = meta.data()?.currentSessionId;
            if (currentSid) {
              sessionCache.set(decoded.uid, { sid: currentSid, expires: now + CACHE_TTL });
            }
          }

          if (currentSid && currentSid !== decoded.sid) {
            console.log(`[AUTH] Session invalidated: uid=${decoded.uid} tokenSid=${decoded.sid} currentSid=${currentSid}`);
            return res.status(401).json({ error: 'Session invalidated by login on another device' });
          }
        }

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
        // Enforce single session for Firebase tokens too
        const now = Date.now();
        const cached = sessionCache.get(fb.uid);
        let currentSid: string | undefined;

        if (cached && cached.expires > now) {
          currentSid = cached.sid;
        } else {
          const meta = await db.collection('user_metadata').doc(fb.uid).get();
          currentSid = meta.data()?.currentSessionId;
          if (currentSid) {
            sessionCache.set(fb.uid, { sid: currentSid, expires: now + CACHE_TTL });
          }
        }

        if (currentSid) {
          if (!fb.sid || currentSid !== fb.sid) {
            console.log(`[AUTH] Firebase session invalidated (SID mismatch or missing): uid=${fb.uid} tokenSid=${fb.sid || 'none'} currentSid=${currentSid}`);
            return res.status(401).json({ error: 'Session invalidated by login on another device' });
          }
        }

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
