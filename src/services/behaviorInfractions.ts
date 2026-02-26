import { db } from '../firebase';
const SUPPORT_EMAIL = process.env.SUPPORT_EMAIL || 'support@howdy.app';
const ONE_WEEK_MS = 7 * 24 * 60 * 60 * 1000;

export type NoticeSeverity = 'info' | 'warning' | 'critical';
export interface ModerationNotice {
  title: string;
  message: string;
  severity: NoticeSeverity;
}
export interface ModerationEvaluation {
  notice: ModerationNotice | null;
  recommendedTakeOffline: boolean;
  recommendedLockUntil: number | null;
  reason: string | null;
}
export interface GoLiveLockStatus {
  isLocked: boolean;
  lockUntil: number | null;
  notice: ModerationNotice | null;
}

function getDayKey(ts: number): string {
  return new Date(ts).toISOString().slice(0, 10);
}

function getWeekKey(ts: number): string {
  const d = new Date(ts);
  const day = d.getUTCDay() || 7;
  d.setUTCDate(d.getUTCDate() + 4 - day);
  const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
  const weekNo = Math.ceil((((d.getTime() - yearStart.getTime()) / 86400000) + 1) / 7);
  return `${d.getUTCFullYear()}-W${weekNo.toString().padStart(2, '0')}`;
}

function lockNotice(untilMs: number): ModerationNotice {
  const until = new Date(untilMs).toLocaleString();
  return {
    title: 'Go Live Temporarily Locked',
    severity: 'critical',
    message:
      `You are temporarily locked from going online until ${until}. ` +
      `If you feel like you have received this notice in error, please reach out to customer support at ${SUPPORT_EMAIL}.`,
  };
}

export async function getGoLiveLockStatus(uid: string): Promise<GoLiveLockStatus> {
  const ref = db.collection('behavior_infractions').doc(uid);
  const snap = await ref.get();
  if (!snap.exists) return { isLocked: false, lockUntil: null, notice: null };

  const data = snap.data() || {};
  const lockUntil = Number((data as any).goLiveLock?.until || 0);
  const now = Date.now();
  if (!lockUntil || lockUntil <= now) {
    if (lockUntil) {
      await ref.set(
        { goLiveLock: { until: null, reason: null }, updatedAt: now },
        { merge: true }
      );
    }
    return { isLocked: false, lockUntil: null, notice: null };
  }
  return { isLocked: true, lockUntil, notice: lockNotice(lockUntil) };
}

/**
 * Phase 1 (safe): data collection only.
 * No lockouts, no queue mutations, no response-shape changes.
 */
export async function recordDeclineInfraction(
  uid: string,
  details: { partnerId?: string | null }
): Promise<ModerationEvaluation> {
  const now = Date.now();
  const dayKey = getDayKey(now);
  const ref = db.collection('behavior_infractions').doc(uid);
  const result: ModerationEvaluation = {
    notice: null,
    recommendedTakeOffline: false,
    recommendedLockUntil: null,
    reason: null,
  };

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? (snap.data() || {}) : {};

    const prevDay = (data as any).dailyDeclines?.dateKey || '';
    const prevCount =
      prevDay === dayKey ? Number((data as any).dailyDeclines?.count || 0) : 0;
    const nextCount = prevCount + 1;
    const existingLockUntil = Number((data as any).goLiveLock?.until || 0);
    const isLocked = existingLockUntil > now;

    if (isLocked) {
      result.notice = lockNotice(existingLockUntil);
      result.recommendedTakeOffline = true;
      result.recommendedLockUntil = existingLockUntil;
      result.reason = 'already_locked';
    } else if (nextCount === 2) {
      result.notice = {
        title: 'You Were Taken Offline',
        severity: 'warning',
        message:
          'You have declined two matches and are being taken offline. ' +
          'Frequent declining of matches can lock you out of availability. ' +
          'Use the Go Online button to go back online. ' +
          `If you feel like you have received this notice in error, please reach out to customer support at ${SUPPORT_EMAIL}.`,
      };
      result.recommendedTakeOffline = true;
      result.reason = 'declines_two_today';
    } else if (nextCount === 4) {
      result.notice = {
        title: 'Warning',
        severity: 'warning',
        message:
          'You have declined multiple matches today. Another decline today will lock you out of going online for one week. ' +
          `If you feel like you have received this notice in error, please reach out to customer support at ${SUPPORT_EMAIL}.`,
      };
      result.reason = 'declines_warning_next_lock';
    } else if (nextCount >= 5) {
      const lockUntil = now + ONE_WEEK_MS;
      result.notice = lockNotice(lockUntil);
      result.recommendedTakeOffline = true;
      result.recommendedLockUntil = lockUntil;
      result.reason = 'declines_week_lock';
    }

    tx.set(
      ref,
      {
        uid,
        updatedAt: now,
        dailyDeclines: {
          dateKey: dayKey,
          count: nextCount,
        },
        ...(result.recommendedLockUntil != null
            ? {
                goLiveLock: {
                  until: result.recommendedLockUntil,
                  reason: result.reason,
                  createdAt: now,
                },
              }
            : {}),
      },
      { merge: true }
    );

    const eventRef = ref.collection('events').doc();
    tx.set(eventRef, {
      type: 'decline',
      createdAt: now,
      dayKey,
      details: {
        partnerId: details.partnerId || null,
        countForDay: nextCount,
      },
      moderation: result,
    });
  });
  return result;
}

export async function recordShortCallInfraction(
  uid: string,
  details: { channelName: string; durationSec: number }
): Promise<ModerationEvaluation> {
  const now = Date.now();
  const weekKey = getWeekKey(now);
  const ref = db.collection('behavior_infractions').doc(uid);
  const result: ModerationEvaluation = {
    notice: null,
    recommendedTakeOffline: false,
    recommendedLockUntil: null,
    reason: null,
  };

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const data = snap.exists ? (snap.data() || {}) : {};

    const prevWeek = (data as any).weeklyShortCalls?.weekKey || '';
    const prevCount =
      prevWeek === weekKey ? Number((data as any).weeklyShortCalls?.count || 0) : 0;
    const nextCount = prevCount + 1;
    const existingLockUntil = Number((data as any).goLiveLock?.until || 0);
    const isLocked = existingLockUntil > now;

    if (isLocked) {
      result.notice = lockNotice(existingLockUntil);
      result.recommendedTakeOffline = true;
      result.recommendedLockUntil = existingLockUntil;
      result.reason = 'already_locked';
    } else if (nextCount === 3) {
      result.notice = {
        title: 'Warning',
        severity: 'warning',
        message:
          'A good faith call should last at least two minutes. Repeated very short calls can result in a temporary lock from going online. ' +
          `If you feel like you have received this notice in error, please reach out to customer support at ${SUPPORT_EMAIL}.`,
      };
      result.reason = 'short_calls_warning';
    } else if (nextCount >= 4) {
      const lockUntil = now + ONE_WEEK_MS;
      result.notice = lockNotice(lockUntil);
      result.recommendedTakeOffline = true;
      result.recommendedLockUntil = lockUntil;
      result.reason = 'short_calls_week_lock';
    }

    tx.set(
      ref,
      {
        uid,
        updatedAt: now,
        weeklyShortCalls: {
          weekKey,
          count: nextCount,
        },
        ...(result.recommendedLockUntil != null
            ? {
                goLiveLock: {
                  until: result.recommendedLockUntil,
                  reason: result.reason,
                  createdAt: now,
                },
              }
            : {}),
      },
      { merge: true }
    );

    const eventRef = ref.collection('events').doc();
    tx.set(eventRef, {
      type: 'short_call',
      createdAt: now,
      weekKey,
      details: {
        channelName: details.channelName,
        durationSec: details.durationSec,
      },
      moderation: result,
    });
  });
  return result;
}
