import crypto from 'crypto';

// Encryption: AES-256-GCM with 12-byte IV
// Env: PII_ENCRYPTION_KEY should be a base64-encoded 32-byte key

function getKey(): Buffer | null {
  const b64 = process.env.PII_ENCRYPTION_KEY || '';
  if (!b64) {
    console.warn('⚠️ PII_ENCRYPTION_KEY not set; PII encryption will be skipped.');
    return null;
  }
  try {
    const key = Buffer.from(b64, 'base64');
    if (key.length !== 32) {
      console.error('❌ PII_ENCRYPTION_KEY must decode to 32 bytes (received %d).', key.length);
      return null;
    }
    return key;
  } catch (e) {
    console.error('❌ Failed to parse PII_ENCRYPTION_KEY (base64 expected):', e);
    return null;
  }
}

export function encryptString(value: string): string | null {
  const key = getKey();
  if (!key) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `v1:${iv.toString('base64')}:${tag.toString('base64')}:${ciphertext.toString('base64')}`;
}

export function decryptString(payload: string): string | null {
  const key = getKey();
  if (!key) return null;
  try {
    const [ver, ivB64, tagB64, dataB64] = String(payload || '').split(':');
    if (ver !== 'v1') throw new Error('Unsupported PII payload version');
    const iv = Buffer.from(ivB64, 'base64');
    const tag = Buffer.from(tagB64, 'base64');
    const data = Buffer.from(dataB64, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(data), decipher.final()]);
    return plain.toString('utf8');
  } catch (e) {
    console.error('❌ Failed to decrypt PII payload:', e);
    return null;
  }
}


