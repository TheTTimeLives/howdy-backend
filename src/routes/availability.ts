import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

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
  let projected = new Date(base);
  while (projected.getTime() < clock.getTime()) {
    projected = new Date(projected.getTime() + 7 * 24 * 60 * 60 * 1000);
  }
  return projected;
}

function nextMonthlyStart(base: Date, clock: Date): Date {
  let projected = new Date(base);
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
    const snap = await db
      .collection('schedules')
      .doc(uid)
      .collection('availability')
      .orderBy('start')
      .get();
    const items = snap.docs.map((d) => ({ id: d.id, ...(d.data() as any) }));

    const upcoming: any[] = [];
    for (const it of items) {
      const start = new Date(Number(it.start));
      const end = new Date(Number(it.end));
      const repeat: RepeatType = (it.repeat as RepeatType) ?? null;
      const typ = (it.type || 'scheduled') as string;
      const durationMs = end.getTime() - start.getTime();
      if (!repeat) {
        if (end.getTime() > now.getTime()) {
          upcoming.push({
            id: it.id,
            type: typ,
            repeat: null,
            start: start.getTime(),
            end: end.getTime(),
            inWindow: now >= start && now <= end,
          });
        }
        continue;
      }
      if (repeat === 'weekly') {
        const nextStart = nextWeeklyStart(start, now);
        const nextEnd = new Date(nextStart.getTime() + durationMs);
        if (nextStart <= horizon) {
          upcoming.push({
            id: it.id,
            type: typ,
            repeat,
            start: nextStart.getTime(),
            end: nextEnd.getTime(),
            inWindow: now >= nextStart && now <= nextEnd,
          });
        }
        continue;
      }
      if (repeat === 'monthly') {
        const nextStart = nextMonthlyStart(start, now);
        const nextEnd = new Date(nextStart.getTime() + durationMs);
        if (nextStart <= horizon) {
          upcoming.push({
            id: it.id,
            type: typ,
            repeat,
            start: nextStart.getTime(),
            end: nextEnd.getTime(),
            inWindow: now >= nextStart && now <= nextEnd,
          });
        }
        continue;
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
availabilityRouter.post('/', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const {
      start, // ms
      end, // ms
      type, // 'live' | 'scheduled'
      repeat, // 'weekly' | 'monthly' | null
      targetUserId, // optional
      dateRangeStart, // ms optional (for weekly bulk)
      dateRangeEnd, // ms optional (for weekly bulk)
    } = req.body || {};

    const typ = (type || 'scheduled').toString();
    const rpt: RepeatType = repeat ? String(repeat) as RepeatType : null;

    if (rpt === 'weekly' && dateRangeStart && dateRangeEnd) {
      const startDate = new Date(Number(dateRangeStart));
      const endDate = new Date(Number(dateRangeEnd));
      // normalize to date, loop days inclusive
      const cursor = new Date(startDate.getFullYear(), startDate.getMonth(), startDate.getDate(), 0, 0, 0, 0);
      const endDay = new Date(endDate.getFullYear(), endDate.getMonth(), endDate.getDate(), 0, 0, 0, 0);
      const created: string[] = [];
      while (cursor.getTime() <= endDay.getTime()) {
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
            createdBy: uid,
            createdAt: Date.now(),
            targetUserId: targetUserId ?? null,
          });
        created.push(ref.id);
        cursor.setDate(cursor.getDate() + 1);
      }
      return res.status(200).json({ ok: true, created });
    }

    const s = Number(start);
    const e = Number(end);
    if (!Number.isFinite(s) || !Number.isFinite(e) || s <= 0 || e <= 0) {
      return res.status(400).json({ error: 'start and end (ms) required' });
    }

    const ref = await db
      .collection('schedules')
      .doc(uid)
      .collection('availability')
      .add({
        start: s,
        end: e,
        type: typ,
        repeat: rpt,
        createdBy: uid,
        createdAt: Date.now(),
        targetUserId: targetUserId ?? null,
      });
    return res.status(200).json({ ok: true, id: ref.id });
  } catch (e) {
    console.error('❌ create availability failed', e);
    return res.status(500).json({ error: 'Failed to create availability' });
  }
});

// DELETE /availability/:id
availabilityRouter.delete('/:id', async (req, res) => {
  const uid = (req as any).uid as string;
  const { id } = req.params;
  try {
    const ref = db.collection('schedules').doc(uid).collection('availability').doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Not found' });
    await ref.delete();
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ delete availability failed', e);
    return res.status(500).json({ error: 'Failed to delete availability' });
  }
});


