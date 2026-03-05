/**
 * Virtual phone numbers for Howdy (E.164 format, +888 prefix).
 * Used for native Contacts/Favorites/Recents integration without real PSTN.
 * Format: +888 + 12 random digits (16 chars total).
 * Stored in user_metadata.virtualNumber only; lookup by number queries user_metadata.
 */
import { db } from '../firebase';
import crypto from 'crypto';

const PREFIX = '+888';
const ID_LENGTH = 12;
const MAX_ATTEMPTS = 10;

function generateRandomDigits(len: number): string {
  const bytes = crypto.randomBytes(len);
  let result = '';
  for (let i = 0; i < len; i++) {
    result += (bytes[i]! % 10).toString();
  }
  return result;
}

export async function ensureVirtualNumber(uid: string): Promise<string> {
  const metaRef = db.collection('user_metadata').doc(uid);
  const metaSnap = await metaRef.get();
  const existing = metaSnap.data()?.virtualNumber as string | undefined;

  if (existing && existing.startsWith(PREFIX) && existing.length === 16) {
    return existing;
  }

  for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
    const digits = generateRandomDigits(ID_LENGTH);
    const number = `${PREFIX}${digits}`;

    try {
      await db.runTransaction(async (tx) => {
        const taken = await tx.get(
          db.collection('user_metadata').where('virtualNumber', '==', number).limit(1),
        );
        if (!taken.empty) throw new Error('collision');
        tx.set(metaRef, { virtualNumber: number }, { merge: true });
      });
      return number;
    } catch (e) {
      if ((e as Error).message === 'collision') continue;
      throw e;
    }
  }

  throw new Error('Failed to generate unique virtual number');
}

export async function lookupUserByVirtualNumber(number: string): Promise<{ userId: string; username?: string } | null> {
  const digits = number.replace(/\D/g, '');
  if (digits.length < 12) return null;
  const full = digits.startsWith('888') && digits.length >= 15
    ? `+${digits.slice(0, 15)}`
    : `${PREFIX}${digits.slice(-12)}`;
  if (!full.startsWith(PREFIX) || full.length !== 16) return null;

  const snap = await db
    .collection('user_metadata')
    .where('virtualNumber', '==', full)
    .limit(1)
    .get();

  if (snap.empty) return null;
  const doc = snap.docs[0]!;
  const userId = doc.id;
  const username = doc.data()?.username as string | undefined;

  return { userId, username };
}
