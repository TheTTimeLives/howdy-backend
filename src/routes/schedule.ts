import express from 'express';
import type { QuerySnapshot } from 'firebase-admin/firestore';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import { canViewScheduleFor } from '../utils/scheduleAuth';

export const scheduleRouter = express.Router();
scheduleRouter.use(express.json());
scheduleRouter.use(verifyJwt);

/** GET /schedule/availability/:userId — raw availability docs (same shape as GET /availability for self). */
scheduleRouter.get('/availability/:userId', async (req, res) => {
  const requester = (req as any).uid as string;
  const userId = String(req.params.userId || '');
  if (!userId) return res.status(400).json({ error: 'userId required' });

  if (!(await canViewScheduleFor(requester, userId))) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const snap = await db
      .collection('schedules')
      .doc(userId)
      .collection('availability')
      .orderBy('start')
      .get();
    const rows = snap.docs.map((d) => ({ id: d.id, ...(d.data() as any) }));
    return res.status(200).json({ availability: rows });
  } catch (e) {
    console.error('schedule availability list failed', e);
    return res.status(500).json({ error: 'Failed to list availability' });
  }
});

/** GET /schedule/confirmed-connections?userId= — map partnerId -> username for calendar dropdown. */
scheduleRouter.get('/confirmed-connections', async (req, res) => {
  const requester = (req as any).uid as string;
  const userId = typeof req.query.userId === 'string' ? String(req.query.userId) : requester;

  if (!(await canViewScheduleFor(requester, userId))) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  try {
    const snap = await db.collection('connections').doc(userId).collection('confirmed').get();
    const connections = snap.docs.map((d) => ({
      id: d.id,
      username: String((d.data() as any)?.username ?? d.id),
    }));
    return res.status(200).json({ connections });
  } catch (e) {
    console.error('schedule confirmed-connections failed', e);
    return res.status(500).json({ error: 'Failed to list connections' });
  }
});

/**
 * GET /schedule/calendar-events?userId=&dayStartMs=&dayEndMs=
 * Call / proposal events where user is sender or partner (not declined/cancelled).
 * Optional day range filters by event start (same as legacy client queries).
 */
scheduleRouter.get('/calendar-events', async (req, res) => {
  const requester = (req as any).uid as string;
  const userId = typeof req.query.userId === 'string' ? String(req.query.userId) : requester;

  if (!(await canViewScheduleFor(requester, userId))) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  const dayStartMs =
    req.query.dayStartMs != null ? Number(req.query.dayStartMs) : null;
  const dayEndMs = req.query.dayEndMs != null ? Number(req.query.dayEndMs) : null;
  const dayFilter =
    dayStartMs != null &&
    dayEndMs != null &&
    Number.isFinite(dayStartMs) &&
    Number.isFinite(dayEndMs);

  try {
    const merge = (snap: QuerySnapshot) => {
      const out: any[] = [];
      for (const doc of snap.docs) {
        const data = doc.data() as any;
        const st = String(data.status || '');
        if (st === 'declined' || st === 'cancelled') continue;
        out.push({ id: doc.id, ...data });
      }
      return out;
    };

    let asSender: any[];
    let asPartner: any[];

    if (dayFilter) {
      const s1 = await db
        .collection('events')
        .where('senderId', '==', userId)
        .where('start', '>=', dayStartMs!)
        .where('start', '<', dayEndMs!)
        .limit(100)
        .get();
      const s2 = await db
        .collection('events')
        .where('partnerId', '==', userId)
        .where('start', '>=', dayStartMs!)
        .where('start', '<', dayEndMs!)
        .limit(100)
        .get();
      asSender = merge(s1);
      asPartner = merge(s2);
    } else {
      const s1 = await db.collection('events').where('senderId', '==', userId).limit(300).get();
      const s2 = await db.collection('events').where('partnerId', '==', userId).limit(300).get();
      asSender = merge(s1);
      asPartner = merge(s2);
    }

    const byId = new Map<string, any>();
    for (const e of [...asSender, ...asPartner]) {
      byId.set(e.id, e);
    }
    return res.status(200).json({ events: [...byId.values()] });
  } catch (e) {
    console.error('schedule calendar-events failed', e);
    return res.status(500).json({ error: 'Failed to list calendar events' });
  }
});

/**
 * POST /schedule/propose-call — create chat proposal message + paired event docs (replaces client Firestore writes).
 */
scheduleRouter.post('/propose-call', async (req, res) => {
  const uid = (req as any).uid as string;
  const { partnerId, startMs, endMs } = req.body || {};
  const partner = typeof partnerId === 'string' ? partnerId : '';
  const start = Number(startMs);
  const end = Number(endMs);
  if (!partner) return res.status(400).json({ error: 'partnerId required' });
  if (!Number.isFinite(start) || !Number.isFinite(end) || start <= 0 || end <= 0) {
    return res.status(400).json({ error: 'startMs and endMs required' });
  }

  const conn = await db.collection('connections').doc(uid).collection('confirmed').doc(partner).get();
  const connRev = await db.collection('connections').doc(partner).collection('confirmed').doc(uid).get();
  if (!conn.exists && !connRev.exists) {
    return res.status(403).json({ error: 'Not a confirmed connection' });
  }

  try {
    const sorted = [uid, partner].sort();
    const chatId = `${sorted[0]}_${sorted[1]}`;

    const messageRef = await db
      .collection('chats')
      .doc(chatId)
      .collection('messages')
      .add({
        senderId: uid,
        type: 'proposal',
        start,
        end,
        status: 'pending',
        timestamp: Date.now(),
      });

    const eventId = `${chatId}_${messageRef.id}`;
    const eventPayload = {
      start,
      end,
      partnerId: partner,
      senderId: uid,
      status: 'pending',
      isProposal: true,
      chatId,
      messageId: messageRef.id,
      createdAt: Date.now(),
    };

    await db.collection('events').doc(eventId).set(eventPayload);

    return res.status(200).json({ ok: true, chatId, messageId: messageRef.id, eventId });
  } catch (e) {
    console.error('schedule propose-call failed', e);
    return res.status(500).json({ error: 'Failed to create proposal' });
  }
});
