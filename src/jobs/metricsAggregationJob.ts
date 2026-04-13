/**
 * Metrics aggregation job: compute KPIs from existing Firestore data.
 * Stores results in metrics_monthly. No BigQuery, no new services — stays in Firestore free tier.
 *
 * Run monthly (e.g. 1st at 02:00). Aggregates the previous calendar month.
 * Configure: METRICS_AGGREGATION_ENABLED (default true).
 */
import { db } from '../firebase';

const SHORT_CALL_THRESHOLD_SEC = 20;

export interface MonthlyMetrics {
  period: string; // "2025-02"
  periodStartMs: number;
  periodEndMs: number;
  computedAt: number;

  // Calls (from calls collection)
  totalCalls: number;
  totalCallDurationSec: number;
  avgCallDurationSec: number;
  shortCalls: number; // duration <= 20s
  shortCallRate: number; // 0-1

  // Auth & activity (from system_activity_audit)
  logins: number;
  callStarted: number;
  callEnded: number;
  moderationEvents: number;
}

export async function runMetricsAggregationJob(
  forMonth?: { year: number; month: number }
): Promise<MonthlyMetrics | null> {
  const enabled =
    String(process.env.METRICS_AGGREGATION_ENABLED || 'true').toLowerCase() === 'true';
  if (!enabled) {
    console.log('[METRICS] Aggregation disabled (METRICS_AGGREGATION_ENABLED=false)');
    return null;
  }

  const now = new Date();
  const target = forMonth ?? {
    year: now.getMonth() === 0 ? now.getFullYear() - 1 : now.getFullYear(),
    month: now.getMonth() === 0 ? 12 : now.getMonth(),
  };

  const periodStart = new Date(target.year, target.month - 1, 1);
  const periodEnd = new Date(target.year, target.month, 0, 23, 59, 59, 999);
  const periodStartMs = periodStart.getTime();
  const periodEndMs = periodEnd.getTime();
  const periodKey = `${target.year}-${String(target.month).padStart(2, '0')}`;

  console.log(`[METRICS] Aggregating ${periodKey} (${periodStart.toISOString()} to ${periodEnd.toISOString()})`);

  // 1. Calls: from calls collection, where endedAt in range
  let totalCalls = 0;
  let totalCallDurationSec = 0;
  let shortCalls = 0;

  const callsSnap = await db
    .collection('calls')
    .where('endedAt', '>=', periodStartMs)
    .where('endedAt', '<=', periodEndMs)
    .get();

  for (const doc of callsSnap.docs) {
    const d = doc.data() || {};
    const startedAt = Number(d.startedAt || 0);
    const endedAt = Number(d.endedAt || 0);
    if (startedAt <= 0 || endedAt <= 0) continue;

    const durationSec = Math.floor((endedAt - startedAt) / 1000);
    totalCalls++;
    totalCallDurationSec += durationSec;
    if (durationSec <= SHORT_CALL_THRESHOLD_SEC) shortCalls++;
  }

  const avgCallDurationSec = totalCalls > 0 ? totalCallDurationSec / totalCalls : 0;
  const shortCallRate = totalCalls > 0 ? shortCalls / totalCalls : 0;

  // 2. Audit events: from system_activity_audit, where createdAt in range
  let logins = 0;
  let callStarted = 0;
  let callEnded = 0;
  let moderationEvents = 0;

  const auditSnap = await db
    .collection('system_activity_audit')
    .where('createdAt', '>=', periodStartMs)
    .where('createdAt', '<=', periodEndMs)
    .get();

  for (const doc of auditSnap.docs) {
    const d = doc.data() || {};
    const action = String(d.action || '');
    const category = String(d.category || '');

    if (action === 'login') logins++;
    else if (action === 'call_started') callStarted++;
    else if (action === 'call_ended') callEnded++;
    else if (category === 'moderation') moderationEvents++;
  }

  const metrics: MonthlyMetrics = {
    period: periodKey,
    periodStartMs,
    periodEndMs,
    computedAt: Date.now(),
    totalCalls,
    totalCallDurationSec,
    avgCallDurationSec,
    shortCalls,
    shortCallRate,
    logins,
    callStarted,
    callEnded,
    moderationEvents,
  };

  await db.collection('metrics_monthly').doc(periodKey).set(metrics, { merge: true });

  console.log(
    `[METRICS] Saved ${periodKey}: ${totalCalls} calls, avg ${avgCallDurationSec.toFixed(1)}s, ` +
      `${shortCalls} short, ${logins} logins, ${moderationEvents} moderation`
  );

  return metrics;
}
