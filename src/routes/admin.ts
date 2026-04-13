import express from 'express';
import { db, auth } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import { logAuditEvent } from '../utils/audit';

async function getUserDisplayInfo(uid: string): Promise<{ userId: string; email?: string; username?: string }> {
  const info: { userId: string; email?: string; username?: string } = { userId: uid };
  try {
    const [authUser, metaSnap] = await Promise.all([
      auth.getUser(uid).catch(() => null),
      db.collection('user_metadata').doc(uid).get(),
    ]);
    if (authUser?.email) info.email = authUser.email;
    const username = metaSnap.data()?.username;
    if (username) info.username = username;
  } catch (_) {}
  return info;
}

export const adminRouter = express.Router();
adminRouter.use(verifyJwt);

async function isSystemAdmin(uid: string): Promise<boolean> {
  const snap = await db.collection('user_metadata').doc(uid).get();
  return snap.data()?.isSystemAdmin === true;
}

adminRouter.get('/me', async (req, res) => {
  const uid = String((req as any).uid || '');
  try {
    const allowed = await isSystemAdmin(uid);
    return res.status(200).json({ isSystemAdmin: allowed });
  } catch (e) {
    return res.status(500).json({ error: 'Failed to check admin status' });
  }
});

adminRouter.get('/system-admins', async (req, res) => {
  const uid = String((req as any).uid || '');
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });

    const snap = await db
      .collection('user_metadata')
      .where('isSystemAdmin', '==', true)
      .limit(200)
      .get();

    const items = snap.docs.map((d) => ({
      uid: d.id,
      username: d.data()?.username ?? '',
      updatedAt: d.data()?.systemAdminUpdatedAt ?? null,
      updatedBy: d.data()?.systemAdminUpdatedBy ?? null,
    }));

    return res.status(200).json({ items });
  } catch (e) {
    console.error('❌ Failed to list system admins:', e);
    return res.status(500).json({ error: 'Failed to list system admins' });
  }
});

adminRouter.post('/system-admins/:targetUid', async (req, res) => {
  const uid = String((req as any).uid || '');
  const targetUid = String(req.params.targetUid || '').trim();
  const enabled = req.body?.enabled === true;
  const reason = String(req.body?.reason || '').trim();
  if (!targetUid) return res.status(400).json({ error: 'Missing targetUid' });
  if (!reason) return res.status(400).json({ error: 'Reason is required' });
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) {
      // Bootstrap path: if no system admins exist yet, allow first grant.
      const anyAdmin = await db
        .collection('user_metadata')
        .where('isSystemAdmin', '==', true)
        .limit(1)
        .get();
      if (!anyAdmin.empty) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }

    await db.collection('user_metadata').doc(targetUid).set(
      {
        isSystemAdmin: enabled,
        systemAdminUpdatedAt: Date.now(),
        systemAdminUpdatedBy: uid,
      },
      { merge: true }
    );

    await logAuditEvent({
      actorUid: uid,
      actorType: 'admin',
      action: enabled ? 'grant_system_admin' : 'revoke_system_admin',
      entityType: 'user_metadata',
      entityId: targetUid,
      metadata: { reason },
      category: 'admin',
    });

    return res.status(200).json({ ok: true, targetUid, isSystemAdmin: enabled });
  } catch (e) {
    console.error('❌ Failed to update system admin flag:', e);
    return res.status(500).json({ error: 'Failed to update system admin flag' });
  }
});

adminRouter.get('/id-collisions', async (req, res) => {
  const uid = String((req as any).uid || '');
  const status = String(req.query.status || 'pending_review');
  const limit = Math.min(Number(req.query.limit || 50), 200);
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });

    const snap = await db
      .collection('identity_collision_cases')
      .where('status', '==', status)
      .limit(limit)
      .get();

    const rawItems = snap.docs
      .map((d) => ({ id: d.id, ...d.data() }))
      .sort((a, b) => Number((b as any).createdAt || 0) - Number((a as any).createdAt || 0));

    const items = await Promise.all(
      rawItems.map(async (item: any) => {
        const userId = String(item.userId || '');
        const candidateUserIds = (item.candidateUserIds as string[] || []);
        const [userInfo, ...candidateInfos] = await Promise.all([
          getUserDisplayInfo(userId),
          ...candidateUserIds.map((u: string) => getUserDisplayInfo(u)),
        ]);
        return {
          ...item,
          userInfo,
          candidateInfos,
        };
      })
    );

    return res.status(200).json({ items });
  } catch (e) {
    console.error('❌ Failed to list collision cases:', e);
    return res.status(500).json({ error: 'Failed to list collision cases' });
  }
});

adminRouter.post('/id-collisions/:caseId/decision', async (req, res) => {
  const uid = String((req as any).uid || '');
  const caseId = String(req.params.caseId || '').trim();
  const decision = String(req.body?.decision || '').trim().toLowerCase();
  const reason = String(req.body?.reason || '').trim();
  if (!caseId) return res.status(400).json({ error: 'Missing caseId' });
  if (!['approve', 'deny'].includes(decision)) {
    return res.status(400).json({ error: 'Decision must be approve or deny' });
  }
  if (!reason) return res.status(400).json({ error: 'Reason is required' });
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });

    const ref = db.collection('identity_collision_cases').doc(caseId);
    const snap = await ref.get();
    if (!snap.exists) return res.status(404).json({ error: 'Case not found' });
    const data = snap.data() || {};
    const targetUid = String(data.userId || '');
    const now = Date.now();

    await ref.set(
      {
        status: 'resolved',
        decision,
        decisionReason: reason,
        reviewedBy: uid,
        reviewedAt: now,
      },
      { merge: true }
    );

    if (targetUid) {
      const verificationStatus = decision === 'approve' ? 'approved' : 'denied';
      await db.collection('user_metadata').doc(targetUid).set(
        {
          verificationStatus,
          reviewDecisionAt: now,
          reviewDecisionBy: uid,
        },
        { merge: true }
      );
    }

    const auditReason = decision === 'approve' ? 'collision_review_approved' : 'collision_review_denied';
    await logAuditEvent({
      actorUid: uid,
      actorType: 'admin',
      action: decision === 'approve' ? 'collision_case_approved' : 'collision_case_denied',
      entityType: 'identity_collision_case',
      entityId: caseId,
      metadata: { reason: auditReason, decisionReason: reason, userId: targetUid, reviewedBy: uid },
      category: 'identity_verification',
    });

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ Failed to resolve collision case:', e);
    return res.status(500).json({ error: 'Failed to resolve collision case' });
  }
});

adminRouter.get('/activity-audit', async (req, res) => {
  const uid = String((req as any).uid || '');
  const actorType = String(req.query.actorType || '').trim();
  const actorUid = String(req.query.actorUid || '').trim();
  const action = String(req.query.action || '').trim();
  const category = String(req.query.category || '').trim();
  const limit = Math.min(Number(req.query.limit || 100), 500);
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });

    let query: FirebaseFirestore.Query = db
      .collection('system_activity_audit')
      .limit(limit);

    if (actorType) {
      query = query.where('actorType', '==', actorType);
    }
    if (actorUid) {
      query = query.where('actorUid', '==', actorUid);
    }
    if (action) {
      query = query.where('action', '==', action);
    }
    if (category) {
      query = query.where('category', '==', category);
    }

    const snap = await query.get();
    const items = snap.docs
      .map((d) => ({ id: d.id, ...d.data() }))
      .sort((a, b) => Number((b as any).createdAt || 0) - Number((a as any).createdAt || 0));
    return res.status(200).json({ items });
  } catch (e) {
    console.error('❌ Failed to fetch activity audit:', e);
    return res.status(500).json({ error: 'Failed to fetch activity audit' });
  }
});

adminRouter.get('/metrics', async (req, res) => {
  const uid = String((req as any).uid || '');
  const limit = Math.min(Number(req.query.limit || 12), 24); // months
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });

    const snap = await db
      .collection('metrics_monthly')
      .orderBy('period', 'desc')
      .limit(limit)
      .get();

    const items = snap.docs.map((d) => ({ id: d.id, ...d.data() }));
    return res.status(200).json({ items });
  } catch (e) {
    console.error('❌ Failed to fetch metrics:', e);
    return res.status(500).json({ error: 'Failed to fetch metrics' });
  }
});

adminRouter.post('/metrics/aggregate', async (req, res) => {
  const uid = String((req as any).uid || '');
  const { year, month } = req.body || {};
  try {
    const allowed = await isSystemAdmin(uid);
    if (!allowed) return res.status(403).json({ error: 'Forbidden' });

    const forMonth =
      typeof year === 'number' && typeof month === 'number' ? { year, month } : undefined;
    const { runMetricsAggregationJob } = await import('../jobs/metricsAggregationJob');
    const metrics = await runMetricsAggregationJob(forMonth);
    return res.status(200).json({ ok: true, metrics });
  } catch (e) {
    console.error('❌ Failed to run metrics aggregation:', e);
    return res.status(500).json({ error: 'Failed to run metrics aggregation' });
  }
});

