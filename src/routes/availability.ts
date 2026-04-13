import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import { canManageAvailabilityFor } from '../utils/scheduleAuth';

export const availabilityRouter = express.Router();
availabilityRouter.use(express.json());
availabilityRouter.use(verifyJwt);

type RepeatType = 'weekly' | 'monthly' | null;

function addMonths(dt: Date, months: number): Date {
  const y = dt.getFullYear() + Math.floor((dt.getMonth() + months) / 12);
  const m = (dt.getMonth() + months) % 12;
  const lastDay = new Date(y, m + 1, 0).getDate();
  const d = Math.min(dt.getDate(), lastDay);
  return new Date(y, m, d, dt.getHours(), dt.getMinutes(), 0, 0);
}

function nextWeeklyStart(base: Date, clock: Date): Date {
  const baseMs = base.getTime();
  const clockMs = clock.getTime();
  if (baseMs >= clockMs) return base;

  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const diff = clockMs - baseMs;
  const weeksToSkip = Math.ceil(diff / weekMs);
  return new Date(baseMs + weeksToSkip * weekMs);
}

function overlapsValidWindow(
  slotStart: number,
  slotEnd: number,
  validFrom: unknown,
  validTo: unknown,
): boolean {
  const vf = validFrom != null && validFrom !== '' ? Number(validFrom) : null;
  const vt = validTo != null && validTo !== '' ? Number(validTo) : null;
  if ((vf == null || !Number.isFinite(vf)) && (vt == null || !Number.isFinite(vt))) {
    return true;
  }
  if (vf != null && Number.isFinite(vf) && slotEnd <= vf) return false;
  if (vt != null && Number.isFinite(vt) && slotStart > vt) return false;
  return true;
}

function nextMonthlyStart(base: Date, clock: Date): Date {
  let projected = new Date(base);
  if (projected.getTime() >= clock.getTime()) return projected;

  // Estimate months to skip to avoid long loops if base is very old
  const yearsDiff = clock.getFullYear() - projected.getFullYear();
  const monthsDiff = clock.getMonth() - projected.getMonth() + (yearsDiff * 12);
  
  if (monthsDiff > 0) {
    projected = addMonths(projected, monthsDiff);
  }
  
  while (projected.getTime() < clock.getTime()) {
    projected = addMonths(projected, 1);
  }
  return projected;
}

// GET /availability
// Lists current user's availability entries ordered by start (raw documents)
availabilityRouter.get('/', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const snap = await db
      .collection('schedules')
      .doc(uid)
      .collection('availability')
      .orderBy('start')
      .get();
    const rows = snap.docs.map((d) => ({ id: d.id, ...(d.data() as any) }));
    return res.status(200).json({ availability: rows });
  } catch (e) {
    console.error('❌ list availability failed', e);
    return res.status(500).json({ error: 'Failed to list availability' });
  }
});

// GET /availability/upcoming?horizonDays=30
// Projects next occurrences for repeating entries anchored to their original start.
availabilityRouter.get('/upcoming', async (req, res) => {
  const uid = (req as any).uid as string;
  const horizonDays = Math.max(1, Math.min(60, Number(req.query?.horizonDays || 30)));
  const now = new Date();
  const horizon = new Date(now.getTime() + horizonDays * 24 * 60 * 60 * 1000);
  try {
    // Optimization: We could filter by end > now - 24h, but that would require a composite index with orderBy('start').
    // Instead, we'll fetch and filter in-memory. For most users, this is still fast enough if data isn't redundant.
    const snap = await db
      .collection('schedules')
      .doc(uid)
      .collection('availability')
      .orderBy('start')
      .get();
    const items = snap.docs.map((d) => ({ id: d.id, ...(d.data() as any) }));

    const upcoming: any[] = [];
    const seenSlots = new Set<string>(); // For deduplication: "type-start-end"

    for (const it of items) {
      const start = new Date(Number(it.start));
      const end = new Date(Number(it.end));
      const repeat: RepeatType = (it.repeat as RepeatType) ?? null;
      const typ = (it.type || 'scheduled') as string;
      const durationMs = end.getTime() - start.getTime();

      let slotStart: number;
      let slotEnd: number;

      if (!repeat) {
        if (end.getTime() < now.getTime()) continue;
        slotStart = start.getTime();
        slotEnd = end.getTime();
      } else if (repeat === 'weekly') {
        const nextStart = nextWeeklyStart(start, now);
        slotStart = nextStart.getTime();
        slotEnd = nextStart.getTime() + durationMs;
      } else if (repeat === 'monthly') {
        const nextStart = nextMonthlyStart(start, now);
        slotStart = nextStart.getTime();
        slotEnd = nextStart.getTime() + durationMs;
      } else {
        continue;
      }

      if (!overlapsValidWindow(slotStart, slotEnd, it.validFrom, it.validTo)) {
        continue;
      }

      if (slotStart <= horizon.getTime()) {
        const key = `${typ}-${slotStart}-${slotEnd}`;
        if (!seenSlots.has(key)) {
          upcoming.push({
            id: it.id,
            type: typ,
            repeat,
            start: slotStart,
            end: slotEnd,
            inWindow: now.getTime() >= slotStart && now.getTime() <= slotEnd,
          });
          seenSlots.add(key);
        }
      }
    }
    upcoming.sort((a, b) => a.start - b.start);
    return res.status(200).json({ upcoming });
  } catch (e) {
    console.error('❌ list upcoming availability failed', e);
    return res.status(500).json({ error: 'Failed to project upcoming availability' });
  }
});

// POST /availability
// Body can represent single entry or weekly across a date range.
// Optional scheduleOwnerUid: write to that user's schedule (staff managing member only).
availabilityRouter.post('/', async (req, res) => {
  const requesterUid = (req as any).uid as string;
  try {
    const {
      start, // ms
      end, // ms
      type, // 'live' | 'scheduled'
      repeat, // 'weekly' | 'monthly' | null
      targetUserId, // optional
      dateRangeStart, // ms optional (for weekly bulk)
      dateRangeEnd, // ms optional (for weekly bulk)
      weekdays, // optional: Dart-style weekday 1=Mon … 7=Sun — limit weekly bulk to these days
      validFrom, // optional ms: start of first calendar day (repeating window)
      validTo, // optional ms: end of last calendar day (repeating window, inclusive)
      scheduleOwnerUid, // optional: defaults to JWT uid
    } = req.body || {};

    const ownerUid =
      scheduleOwnerUid != null && String(scheduleOwnerUid).trim()
        ? String(scheduleOwnerUid).trim()
        : requesterUid;

    if (ownerUid !== requesterUid && !(await canManageAvailabilityFor(requesterUid, ownerUid))) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const uid = ownerUid;

    const typ = (type || 'scheduled').toString();
    const rpt: RepeatType = repeat ? String(repeat) as RepeatType : null;

    const weeklyValidFrom =
      validFrom != null ? Number(validFrom) : dateRangeStart != null ? Number(dateRangeStart) : null;
    const weeklyValidTo = validTo != null ? Number(validTo) : null;

    if (rpt === 'weekly' && dateRangeStart && dateRangeEnd) {
      const startDate = new Date(Number(dateRangeStart));
      const endDate = new Date(Number(dateRangeEnd));
      // normalize to date, loop days inclusive
      const cursor = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate(), 0, 0, 0, 0);
      const endDay = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate(), 0, 0, 0, 0);
      const created: string[] = [];
      const daysCreated = new Set<number>(); // Track which days of the week we've already created an entry for

      // Optional filter: weekdays as Dart DateTime.weekday (1=Mon … 7=Sun) → JS getDay() (0=Sun … 6=Sat)
      let allowedJsDays: Set<number> | null = null;
      if (Array.isArray(weekdays) && weekdays.length > 0) {
        allowedJsDays = new Set(
          weekdays.map((w: any) => {
            const d = Number(w);
            if (!Number.isFinite(d)) return -1;
            // Dart 7 = Sunday → JS 0; Dart 1–6 = JS 1–6
            return d === 7 ? 0 : d;
          }).filter((n) => n >= 0 && n <= 6),
        );
      }

      while (cursor.getTime() <= endDay.getTime()) {
        const dayOfWeek = cursor.getDay();
        if (allowedJsDays && !allowedJsDays.has(dayOfWeek)) {
          cursor.setDate(cursor.getDate() + 1);
          continue;
        }
        if (!daysCreated.has(dayOfWeek)) {
          const s = new Date(cursor.getFullYear(), cursor.getMonth(), cursor.getDate(), new Date(Number(start)).getHours(), new Date(Number(start)).getMinutes(), 0, 0);
          const e = new Date(cursor.getFullYear(), cursor.getMonth(), cursor.getDate(), new Date(Number(end)).getHours(), new Date(Number(end)).getMinutes(), 0, 0);
          const ref = await db
            .collection('schedules')
            .doc(uid)
            .collection('availability')
            .add({
              start: s.getTime(),
              end: e.getTime(),
              type: typ,
              repeat: 'weekly',
              createdBy: requesterUid,
              createdAt: Date.now(),
              targetUserId: targetUserId ?? null,
              validFrom: Number.isFinite(weeklyValidFrom) ? weeklyValidFrom : null,
              validTo: weeklyValidTo != null && Number.isFinite(weeklyValidTo) ? weeklyValidTo : null,
            });
          created.push(ref.id);
          daysCreated.add(dayOfWeek);
          
          // Optimization: If we've covered all 7 days of the week, we can stop
          if (daysCreated.size === 7) break;
        }
        cursor.setDate(cursor.getDate() + 1);
      }
      return res.status(200).json({ ok: true, created });
    }

    const s = Number(start);
    const e = Number(end);
    if (!Number.isFinite(s) || !Number.isFinite(e) || s <= 0 || e <= 0) {
      return res.status(400).json({ error: 'start and end (ms) required' });
    }

    const singleValidFrom = validFrom != null ? Number(validFrom) : null;
    const singleValidTo = validTo != null ? Number(validTo) : null;

    const ref = await db
      .collection('schedules')
      .doc(uid)
      .collection('availability')
      .add({
        start: s,
        end: e,
        type: typ,
               repeat: rpt,
        createdBy: requesterUid,
        createdAt: Date.now(),
        targetUserId: targetUserId ?? null,
        validFrom:
          (rpt === 'weekly' || rpt === 'monthly') &&
          singleValidFrom != null &&
          Number.isFinite(singleValidFrom)
            ? singleValidFrom
            : null,
        validTo:
          (rpt === 'weekly' || rpt === 'monthly') &&
          singleValidTo != null &&
          Number.isFinite(singleValidTo)
            ? singleValidTo
            : null,
      });
    return res.status(200).json({ ok: true, id: ref.id });
  } catch (e) {
    console.error('❌ create availability failed', e);
    return res.status(500).json({ error: 'Failed to create availability' });
  }
});

// DELETE /availability/:id?scheduleOwnerUid= (optional; defaults to JWT user)
availabilityRouter.delete('/:id', async (req, res) => {
  const requesterUid = (req as any).uid as string;
  const { id } = req.params;
  const rawOwner =
    typeof req.query.scheduleOwnerUid === 'string' ? req.query.scheduleOwnerUid.trim() : '';
  const ownerUid = rawOwner || requesterUid;

  if (ownerUid !== requesterUid && !(await canManageAvailabilityFor(requesterUid, ownerUid))) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const ref = db.collection('schedules').doc(ownerUid).collection('availability').doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.delete();
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ delete availability failed', e);
    return res.status(500).json({ error: 'Failed to delete availability' });
  }
});


