import { db } from '../firebase';

type ActorType = 'admin' | 'user' | 'system';

/**
 * Action categories for filtering system activity in the audit UI.
 * Add new actions to the mapping below when extending audit coverage.
 */
export const ACTION_CATEGORIES = [
  'admin',
  'auth',
  'identity_verification',
  'calls',
  'moderation',
  'user',
  'system',
] as const;

export type ActionCategory = (typeof ACTION_CATEGORIES)[number];

/** Maps action strings to categories. Used when category is not explicitly set. */
const ACTION_TO_CATEGORY: Record<string, ActionCategory> = {
  grant_system_admin: 'admin',
  revoke_system_admin: 'admin',
  collision_case_approved: 'identity_verification',
  collision_case_denied: 'identity_verification',
  collision_review_approved: 'identity_verification',
  collision_review_denied: 'identity_verification',
  login: 'auth',
  logout: 'auth',
  session_invalidated: 'auth',
  call_started: 'calls',
  call_ended: 'calls',
  short_call_infraction: 'moderation',
  decline_infraction: 'moderation',
  match_timeout_infraction: 'moderation',
  moderation_flagged: 'moderation',
  user_profile_updated: 'user',
  verification_status_changed: 'identity_verification',
};

function getCategoryForAction(action: string): ActionCategory {
  return ACTION_TO_CATEGORY[action] ?? 'system';
}

export async function logAuditEvent(params: {
  actorUid?: string | null;
  actorType: ActorType;
  action: string;
  entityType: string;
  entityId?: string | null;
  metadata?: Record<string, any>;
  /** Optional. If omitted, derived from action via ACTION_TO_CATEGORY. */
  category?: ActionCategory;
}) {
  try {
    const now = Date.now();
    const category = params.category ?? getCategoryForAction(params.action);
    await db.collection('system_activity_audit').add({
      actorUid: params.actorUid ?? null,
      actorType: params.actorType,
      action: params.action,
      entityType: params.entityType,
      entityId: params.entityId ?? null,
      metadata: params.metadata ?? {},
      category,
      createdAt: now,
    });
  } catch (e) {
    console.warn('⚠️ Failed to write audit event', e);
  }
}

