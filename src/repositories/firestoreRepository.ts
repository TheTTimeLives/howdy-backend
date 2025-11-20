import { db } from '../firebase';
import { z } from 'zod';

export class FirestoreRepository<T extends { id: string }> {
  private collectionName: string;
  private schema: z.ZodType<T>;

  constructor(collectionName: string, schema: z.ZodType<T>) {
    this.collectionName = collectionName;
    this.schema = schema;
  }

  async get(id: string): Promise<T | null> {
    const snap = await db.collection(this.collectionName).doc(id).get();
    if (!snap.exists) return null;
    const data = { id: snap.id, ...snap.data() } as any;
    return this.schema.parse(data);
  }

  async set(entity: T): Promise<void> {
    const parsed = this.schema.parse(entity);
    const { id, ...rest } = parsed as any;
    await db.collection(this.collectionName).doc(id).set(rest, { merge: true });
  }

  async delete(id: string): Promise<void> {
    await db.collection(this.collectionName).doc(id).delete();
  }
}


