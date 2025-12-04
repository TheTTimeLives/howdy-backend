import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const eventsRouter = express.Router();

eventsRouter.use(express.json());

// Public listing of events (for marketplace)
eventsRouter.get('/public', async (req, res) => {
  try {
    const tag = typeof req.query.tag === 'string' ? String(req.query.tag) : null;
    let query: FirebaseFirestore.Query = db.collection('events').where('visibility', '==', 'public');
    if (tag) {
      query = query.where('tags', 'array-contains', tag);
    }
    const snap = await query.orderBy('startAt', 'asc').limit(200).get();
    const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    return res.status(200).json({ events: rows });
  } catch (e) {
    console.error('❌ list public events failed', e);
    return res.status(500).json({ error: 'Failed to list events' });
  }
});

// Auth required for creating events
eventsRouter.use(verifyJwt);

// Create an event (group-scoped)
eventsRouter.post('/', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const {
      groupId,
      title,
      description,
      tags, // array of strings
      startAt, // ms
      endAt, // ms optional
      visibility, // 'public' | 'group' (default public for marketplace)
    } = req.body || {};

    if (!groupId) return res.status(400).json({ error: 'groupId required' });
    if (!title || typeof title !== 'string' || !title.trim()) {
      return res.status(400).json({ error: 'title required' });
    }
    const start = Number(startAt);
    if (!Number.isFinite(start) || start <= 0) {
      return res.status(400).json({ error: 'startAt (ms) required' });
    }
    const end = endAt != null ? Number(endAt) : null;
    const tagList: string[] = Array.isArray(tags) ? tags.map((t: any) => String(t).toLowerCase()) : [];
    const vis: string = (visibility || 'public').toString();

    // Authorization: require membership role in this group
    const memberDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    if (!memberDoc.exists) {
      return res.status(403).json({ error: 'Not a member of this group' });
    }
    const role = (memberDoc.data()?.role || '').toString();
    const canCreate = ['super-admin', 'admin', 'coordinator'].includes(role);
    if (!canCreate) {
      return res.status(403).json({ error: 'Insufficient permissions to create events' });
    }

    // Snapshot group name to denormalize for list rendering
    let groupName: string | null = null;
    try {
      const gdoc = await db.collection('groups').doc(groupId).get();
      groupName = (gdoc.data()?.name as string) || null;
    } catch {}

    const ref = db.collection('events').doc();
    const payload = {
      title: title.trim(),
      description: (description || '').toString(),
      tags: tagList,
      visibility: vis,
      groupId,
      ...(groupName ? { groupName } : {}),
      createdBy: uid,
      createdAt: Date.now(),
      startAt: start,
      endAt: end,
    };
    await ref.set(payload);
    return res.status(200).json({ ok: true, id: ref.id });
  } catch (e) {
    console.error('❌ create event failed', e);
    return res.status(500).json({ error: 'Failed to create event' });
  }
});

// List my events
eventsRouter.get('/mine', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const snap = await db.collection('events').where('createdBy', '==', uid).orderBy('createdAt', 'desc').limit(200).get();
    const rows = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    return res.status(200).json({ events: rows });
  } catch (e) {
    console.error('❌ list my events failed', e);
    return res.status(500).json({ error: 'Failed to list my events' });
  }
});

// Update my event
eventsRouter.patch('/:id', async (req, res) => {
  const uid = (req as any).uid as string;
  const { id } = req.params;
  try {
    const ref = db.collection('events').doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Event not found' });
    if ((doc.data()?.createdBy || '') !== uid) {
      return res.status(403).json({ error: 'Not your event' });
    }
    const allowed: any = {};
    if (typeof req.body?.title === 'string') allowed.title = String(req.body.title).trim();
    if (typeof req.body?.description === 'string') allowed.description = String(req.body.description);
    if (Array.isArray(req.body?.tags)) {
      allowed.tags = (req.body.tags as any[]).map((t: any) => String(t).toLowerCase());
    }
    if (req.body?.startAt != null) allowed.startAt = Number(req.body.startAt);
    if (req.body?.endAt != null) allowed.endAt = Number(req.body.endAt);
    await ref.set(allowed, { merge: true });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ update event failed', e);
    return res.status(500).json({ error: 'Failed to update event' });
  }
});

// Delete my event
eventsRouter.delete('/:id', async (req, res) => {
  const uid = (req as any).uid as string;
  const { id } = req.params;
  try {
    const ref = db.collection('events').doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Event not found' });
    if ((doc.data()?.createdBy || '') !== uid) {
      return res.status(403).json({ error: 'Not your event' });
    }
    await ref.delete();
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ delete event failed', e);
    return res.status(500).json({ error: 'Failed to delete event' });
  }
});

// Inquire to partner on an event (creates a subdocument)
eventsRouter.post('/:id/inquire', async (req, res) => {
  const uid = (req as any).uid as string;
  const { id } = req.params;
  try {
    const ref = db.collection('events').doc(id);
    const doc = await ref.get();
    if (!doc.exists) return res.status(404).json({ error: 'Event not found' });
    const inquiryRef = ref.collection('inquiries').doc(uid);
    await inquiryRef.set({
      uid,
      createdAt: Date.now(),
    }, { merge: true });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ inquire failed', e);
    return res.status(500).json({ error: 'Failed to inquire' });
  }
});


