/**
 * Audit retention job: delete system_activity_audit docs older than retention period.
 * Configure via AUDIT_RETENTION_DAYS (default: 30).
 * Set to 0 to disable deletion.
 */
import { db } from '../firebase';

const DEFAULT_RETENTION_DAYS = 30;
const BATCH_SIZE = 500;

export async function runAuditRetentionJob(): Promise<{ deleted: number }> {
  const retentionDays = Math.max(
    0,
    parseInt(String(process.env.AUDIT_RETENTION_DAYS || DEFAULT_RETENTION_DAYS), 10)
  );

  if (retentionDays <= 0) {
    console.log('[AUDIT_RETENTION] Disabled (AUDIT_RETENTION_DAYS=0 or invalid)');
    return { deleted: 0 };
  }

  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  let totalDeleted = 0;

  // Firestore batch delete: query in batches, delete each batch
  while (true) {
    const snap = await db
      .collection('system_activity_audit')
      .where('createdAt', '<', cutoffMs)
      .limit(BATCH_SIZE)
      .get();

    if (snap.empty) break;

    const batch = db.batch();
    snap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();
    totalDeleted += snap.size;

    if (snap.size < BATCH_SIZE) break;
  }

  if (totalDeleted > 0) {
    console.log(`[AUDIT_RETENTION] Deleted ${totalDeleted} audit records older than ${retentionDays} days`);
  }

  return { deleted: totalDeleted };
}
