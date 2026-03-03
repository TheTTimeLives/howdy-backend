import { db } from '../firebase';

type ActorType = 'admin' | 'user' | 'system';

export async function logAuditEvent(params: {
  actorUid?: string | null;
  actorType: ActorType;
  action: string;
  entityType: string;
  entityId?: string | null;
  metadata?: Record<string, any>;
}) {
  try {
    const now = Date.now();
    await db.collection('system_activity_audit').add({
      actorUid: params.actorUid ?? null,
      actorType: params.actorType,
      action: params.action,
      entityType: params.entityType,
      entityId: params.entityId ?? null,
      metadata: params.metadata ?? {},
      createdAt: now,
    });
  } catch (e) {
    console.warn('⚠️ Failed to write audit event', e);
  }
}

