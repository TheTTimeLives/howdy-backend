// src/routes/groups.ts
import express from 'express';
import crypto from 'crypto';
import { FieldValue } from 'firebase-admin/firestore';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import { sendEmail } from '../utils/email';
import { decryptString } from '../utils/pii';

export const groupsRouter = express.Router();

/* Parse JSON here too (guard against mount-order mistakes) */
groupsRouter.use(express.json());

/**
 * Resolve the public base URL for invite/landing links during dev.
 * Priority:
 * 1) INVITE_LANDING_BASE_URL (computed by dev.sh to point at Functions/main tunnel)
 * 2) PUBLIC_BASE_URL (main ngrok tunnel for backend)
 * 3) API_BASE_URL / BACKEND_BASE_URL
 * 4) localhost fallback
 */
function resolvePublicBase(): string {
  return (
    process.env.INVITE_LANDING_BASE_URL ||
    process.env.PUBLIC_BASE_URL ||
    process.env.API_BASE_URL ||
    process.env.BACKEND_BASE_URL ||
    'http://localhost:5000'
  );
}

/* -------------------- PUBLIC: invite info (JSON) -------------------- */
// GET /groups/invite-info/:token
groupsRouter.get('/invite-info/:token', async (req, res) => {
  const token = String(req.params.token || '');
  if (!token) return res.status(400).json({ error: 'Missing token' });
  try {
    const doc = await db.collection('group_invites').doc(token).get();
    if (!doc.exists) return res.status(404).json({ error: 'Invalid token' });
    const inv = doc.data() as any;
    if (Date.now() > (inv.expiresAt || 0)) {
      return res.status(400).json({ error: 'Invite expired' });
    }
    const groupSnap = await db.collection('groups').doc(inv.groupId).get();
    const group = groupSnap.data() || {};
    return res.status(200).json({
      email: inv.email || null,
      role: inv.role || 'member',
      groupId: inv.groupId,
      groupName: group.name || 'Howdy Group',
      groupCode: group.groupCode || null,
    });
  } catch (e) {
    console.error('❌ invite info failed', e);
    return res.status(500).json({ error: 'Failed to load invite' });
  }
});

/* -------------------- PUBLIC: invite landing (HTML) -------------------- */
// GET /groups/invite/:token
groupsRouter.get('/invite/:token', (req, res) => {
  const token = String(req.params.token || '');
  const role  = req.query.role ? String(req.query.role) : '';
  if (!token) return res.status(400).send('Missing invite token');

  const deep = `howdy://accept-invite?token=${encodeURIComponent(token)}${
    role ? `&role=${encodeURIComponent(role)}` : ''
  }`;

  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  return res.status(200).send(`<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Accept invite • Howdy</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Inter, sans-serif; background:#f7f7f8; padding:24px; }
      .card { max-width:560px; margin: 40px auto; background:#fff; border:1px solid #e6e6eb; border-radius:12px; padding:20px; }
      .btn { display:inline-block; padding:12px 16px; border-radius:10px; background:#d37f1c; color:#fff; font-weight:600; text-decoration:none; }
      .muted { color:#666; font-size:14px; }
    </style>
  </head>
  <body>
    <div class="card">
      <h2>Open Howdy to accept your invite</h2>
      <p>If the app doesn't open automatically, tap the button:</p>
      <p><a class="btn" href="${deep}">Open in the app</a></p>
      <p class="muted">If you don't have the app installed yet, install it and then come back to this link.</p>
    </div>
    <script>window.location.href = ${JSON.stringify(deep)};</script>
  </body>
</html>`);
});

/* -------------------- AUTH REQUIRED below this line -------------------- */
groupsRouter.use(verifyJwt);

/* === Protected routes === */

// POST /groups → ensure a primary group exists for current user; create if missing
groupsRouter.post('/', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const metaRef = db.collection('user_metadata').doc(uid);
    const meta = await metaRef.get();
    const data = meta.data() || {};
    if (data.primaryGroupId) {
      return res.status(200).json({ groupId: data.primaryGroupId, existed: true });
    }

    const accountType = (data.accountType || 'individual').toString();
    const userDoc = await db.collection('users').doc(uid).get();
    const email = userDoc.data()?.email || 'user@example.com';

    const groupRef = db.collection('groups').doc();
    const groupId = groupRef.id;
    const groupCode = crypto.randomBytes(3).toString('hex').toUpperCase();
    const inferredName = accountType === 'organization'
      ? email.split('@')[1]?.split('.')?.[0] || 'Organization'
      : email.split('@')[0] || 'Carer';

    await groupRef.set({
      name: inferredName,
      type: accountType,
      createdBy: uid,
      createdAt: Date.now(),
      tier: 'trial',
      trialEndsAt: Date.now() + 7 * 24 * 60 * 60 * 1000,
      groupCode,
    });

    await groupRef.collection('members').doc(uid).set({
      uid,
      email,
      role: 'super-admin',
      addedAt: Date.now(),
      status: 'active',
    });

    await metaRef.set({ primaryGroupId: groupId }, { merge: true });
    return res.status(200).json({ groupId, existed: false });
  } catch (e) {
    console.error('❌ create/ensure group failed', e);
    return res.status(500).json({ error: 'Failed to ensure group' });
  }
});

// GET /groups/me → list groups where current user is a member (with role)
groupsRouter.get('/me', async (req, res) => {
  const uid = (req as any).uid as string;
  try {
    const snap = await db.collection('groups').get();
    const groups: any[] = [];
    for (const doc of snap.docs) {
      // Prefer membership documents keyed by UID; if not present, fall back to a document
      // where the stored field `uid` matches the current user.
      let memberSnap = await doc.ref.collection('members').doc(uid).get();
      if (!memberSnap.exists) {
        const alt = await doc.ref
          .collection('members')
          .where('uid', '==', uid)
          .limit(1)
          .get();
        if (!alt.empty) {
          memberSnap = alt.docs[0];
        }
      }
      if (memberSnap.exists) {
        const data = doc.data();
        const m = (memberSnap.data() as any) || {};
        groups.push({ id: doc.id, ...data, role: m.role || 'member' });
      }
    }
    return res.status(200).json({ groups });
  } catch (e) {
    console.error('❌ /groups/me failed', e);
    return res.status(500).json({ error: 'Failed to load groups' });
  }
});

// POST /groups/:groupId/members → add or update a member with role (creates invite for email-only)
groupsRouter.post('/:groupId/members', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId } = req.params;
  const { memberId, email, role, guardianUid: forcedGuardianUid } = req.body || {};

  // --- Debug logging to help if this regresses ---
  console.log('[POST /groups/:groupId/members] groupId=%s body=%j', groupId, req.body);

  if (!memberId && !email) return res.status(400).json({ error: 'memberId or email required' });
  if (!role) return res.status(400).json({ error: 'role required' });

  try {
    // simple authorization: only admins can add/update
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const adminRole = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(adminRole)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    // Validate requested role against allowed roles for this group type
    const groupDoc = await db.collection('groups').doc(groupId).get();
    const groupType = (groupDoc.data()?.type || 'carer').toString();
    const requestedRole = String(role);
    const baseAssignable = ['super-admin', 'admin', 'team-lead', 'volunteer', 'member']; // carer/viewer removed globally
    const carerAssignable = ['admin', 'member'];
    const allowedRoles = groupType === 'carer' ? carerAssignable : baseAssignable;
    if (!allowedRoles.includes(requestedRole)) {
      return res.status(400).json({ error: `Role not allowed for this group (${requestedRole})` });
    }

    const targetId = memberId || email;
    const memberRef = db.collection('groups').doc(groupId).collection('members').doc(targetId);

    // Determine guardian
    let guardianUid: string | null = null;
    let guardianEmail: string | null = null;
    if (role === 'member') {
      let candidateUid: string | null = null;
      if (forcedGuardianUid && typeof forcedGuardianUid === 'string') {
        candidateUid = forcedGuardianUid;
      } else {
        candidateUid = uid; // fallback to acting admin
      }
      if (candidateUid) {
        const gdoc = await db.collection('groups').doc(groupId).collection('members').doc(candidateUid).get();
        const gRole = gdoc.data()?.role;
        if (gdoc.exists && ['super-admin', 'admin'].includes(gRole)) {
          guardianUid = candidateUid;
          try {
            const udoc = await db.collection('users').doc(candidateUid).get();
            guardianEmail = (udoc.data()?.email as string) || null;
          } catch {}
        } else {
          guardianUid = uid;
          try {
            const udoc = await db.collection('users').doc(uid).get();
            guardianEmail = (udoc.data()?.email as string) || null;
          } catch {}
        }
      }
    }

    // Email-only invitations are stored as status 'pending'
    const memberPayload: any = {
      uid: memberId || null,
      email: email || null,
      role,
      addedAt: Date.now(),
      status: memberId ? 'active' : 'pending',
    };
    if (role === 'member') {
      memberPayload.guardianUid = guardianUid || uid;
      if (guardianEmail) memberPayload.guardianEmail = guardianEmail;
    }
    await memberRef.set(memberPayload, { merge: true });

    if (email && !memberId) {
      // --- This branch creates the invite ---
      const token = crypto.randomBytes(24).toString('hex');
      const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000; // 7 days
      await db.collection('group_invites').doc(token).set({
        groupId,
        email,
        role,
        invitedBy: uid,
        createdAt: Date.now(),
        expiresAt,
      });

      console.log('[INVITE] Created group_invites/%s for %s (group %s, role %s)', token, email, groupId, role);

      // Load group to include name in email
      let groupName = 'Howdy Group';
      try {
        const gdoc = await db.collection('groups').doc(groupId).get();
        groupName = (gdoc.data()?.name as string) || groupName;
      } catch {}

      const appDeepLink = `howdy://accept-invite?token=${token}${role ? `&role=${encodeURIComponent(role)}` : ''}`;

      try {
        const publicBase = resolvePublicBase();
        const webLink = `${publicBase}/invite.html?token=${encodeURIComponent(token)}${role ? `&role=${encodeURIComponent(role)}` : ''}`;
        await sendEmail(
          email,
          `You're invited to ${groupName} on Howdy`,
          `You're invited to ${groupName} on Howdy.\n\nOpen in the app: ${webLink}`,
          `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;font-size:14px;color:#222;line-height:1.5">
            <p>Hi,</p>
            <p>You have been invited to join <strong>${groupName}</strong> on Howdy.</p>
            <p>
              <a href="${webLink}" style="
                display:inline-block;
                background:#d37f1c;
                color:#fff;
                padding:12px 16px;
                border-radius:8px;
                text-decoration:none;
                font-weight:600;">Accept in the app</a>
            </p>
            <p>Thanks,<br/>The Howdy Team</p>
          </div>`
        );
      } catch (e) {
        console.warn('⚠️ Failed to send invite email', e);
      }
    }

    // If we created an email invite above, expose the deep link for UI copy/share
    // Note: when no email invite was created (memberId path), we simply return ok
    try {
      if (req.body?.email && !req.body?.memberId) {
        const role = String(req.body?.role || 'member');
        const tokenDoc = await db
          .collection('group_invites')
          .where('email', '==', String(req.body.email))
          .orderBy('createdAt', 'desc')
          .limit(1)
          .get();
        const token = tokenDoc.empty ? null : tokenDoc.docs[0].id;
        if (token) {
          const publicBase = resolvePublicBase();
          const inviteLink = `${publicBase}/invite.html?token=${encodeURIComponent(token)}${role ? `&role=${encodeURIComponent(role)}` : ''}`;
          return res.status(200).json({ ok: true, inviteToken: token, inviteLink });
        }
      }
    } catch (_) {}

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ add member failed', e);
    return res.status(500).json({ error: 'Failed to add member' });
  }
});

// GET /groups/:groupId/members
groupsRouter.get('/:groupId/members', async (req, res) => {
  const { groupId } = req.params;
  try {
    const snap = await db.collection('groups').doc(groupId).collection('members').get();
    const docs = snap.docs;
    const members = await Promise.all(
      docs.map(async (d) => {
        const base: any = { id: d.id, ...d.data() };
        const uid = base.uid;
        if (uid && typeof uid === 'string') {
          try {
            const udoc = await db.collection('users').doc(uid).get();
            const udata = udoc.data() || {} as any;
            const pii = udata.pii || {};
            console.log('🔊 pii:', pii);
            const firstName = typeof pii.firstNameEnc === 'string' ? decryptString(pii.firstNameEnc) : null;
            const lastName = typeof pii.lastNameEnc === 'string' ? decryptString(pii.lastNameEnc) : null;
            if (firstName || lastName) {
              base.firstName = firstName;
              base.lastName = lastName;
            }
          } catch (_) {}
        }
        return base;
      })
    );
    return res.status(200).json({ members });
  } catch (e) {
    console.error('❌ list members failed', e);
    return res.status(500).json({ error: 'Failed to list members' });
  }
});

// DELETE /groups/:groupId/members/:memberDocId
groupsRouter.delete('/:groupId/members/:memberDocId', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId, memberDocId } = req.params;
  try {
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const role = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const memberRef = db.collection('groups').doc(groupId).collection('members').doc(memberDocId);
    const memberDoc = await memberRef.get();
    if (!memberDoc.exists) {
      return res.status(404).json({ error: 'Member not found' });
    }

    await memberRef.delete();

    // Best-effort device unpair if memberDocId is a real uid
    try {
      const userMetaRef = db.collection('user_metadata').doc(memberDocId);
      const userMetaSnap = await userMetaRef.get();
      if (userMetaSnap.exists) {
        const data = (userMetaSnap.data() || {}) as any;
        const isMember = String(data.accountType || '') === 'member';
        const isPrimaryGroup = String(data.primaryGroupId || '') === String(groupId);
        if (isMember && isPrimaryGroup) {
          const deviceId = data?.allowedDevice?.deviceId as string | undefined;
          await userMetaRef.set({
            allowedDevice: null,
            deviceChallenge: null,
            primaryGroupId: null,
            unmanagedSince: Date.now(),
          }, { merge: true });
          if (deviceId) {
            await db.collection('device_index').doc(deviceId).set(
              { status: 'unpaired', uid: null, loginChallenge: null },
              { merge: true }
            );
          }
        }
      }
    } catch (e) {
      console.warn('⚠️ device unpair on member removal failed (non-fatal):', e);
    }

    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ remove member failed', e);
    return res.status(500).json({ error: 'Failed to remove member' });
  }
});

// POST /groups/:groupId/invite → create shareable invite link (no email), returns { inviteToken, inviteLink }
groupsRouter.post('/:groupId/invite', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId } = req.params;
  const role = String(req.body?.role || '').trim() || 'member';

  try {
    // Require admin
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const adminRole = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(adminRole)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    // Validate requested role for group type
    const groupDoc = await db.collection('groups').doc(groupId).get();
    if (!groupDoc.exists) return res.status(404).json({ error: 'Group not found' });
    const groupType = (groupDoc.data()?.type || 'carer').toString();
    const baseAssignable = ['super-admin', 'admin', 'team-lead', 'volunteer', 'member'];
    const carerAssignable = ['admin', 'member'];
    const allowedRoles = groupType === 'carer' ? carerAssignable : baseAssignable;
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ error: `Role not allowed for this group (${role})` });
    }

    // Create token
    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
    await db.collection('group_invites').doc(token).set({
      groupId,
      email: null,
      role,
      invitedBy: uid,
      createdAt: Date.now(),
      expiresAt,
    });

    const publicBase = resolvePublicBase();

    // Use static landing that deep-links into app when available
    const inviteLink = `${publicBase}/invite.html?token=${encodeURIComponent(token)}${role ? `&role=${encodeURIComponent(role)}` : ''}`;

    console.log('[INVITE share] group=%s role=%s base=%s link=%s', groupId, role, publicBase, inviteLink);
    return res.status(200).json({ ok: true, inviteToken: token, inviteLink });
  } catch (e) {
    console.error('❌ create shareable invite failed', e);
    return res.status(500).json({ error: 'Failed to create invite' });
  }
});

// --- Group Codes ---
groupsRouter.post('/:groupId/codes', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId } = req.params;
  try {
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const role = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    await db.collection('groups').doc(groupId).collection('codes').doc(code).set({
      code,
      createdAt: Date.now(),
      createdBy: uid,
      active: true,
    });
    return res.status(200).json({ code });
  } catch (e) {
    console.error('❌ create code failed', e);
    return res.status(500).json({ error: 'Failed to create code' });
  }
});

groupsRouter.get('/:groupId/codes', async (req, res) => {
  const { groupId } = req.params;
  try {
    const snap = await db.collection('groups').doc(groupId).collection('codes').orderBy('createdAt', 'desc').get();
    const codes = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    return res.status(200).json({ codes });
  } catch (e) {
    console.error('❌ list codes failed', e);
    return res.status(500).json({ error: 'Failed to list codes' });
  }
});

groupsRouter.post('/:groupId/codes/:code/email', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId, code } = req.params;
  const emails = Array.isArray(req.body?.emails) ? req.body.emails.map((e: any) => String(e)) : null;
  try {
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const role = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    const codeDoc = await db.collection('groups').doc(groupId).collection('codes').doc(code).get();
    if (!codeDoc.exists) return res.status(404).json({ error: 'Code not found' });

    let targets: string[] = [];
    if (emails && emails.length > 0) {
      targets = emails;
    } else {
      const membersSnap = await db.collection('groups').doc(groupId).collection('members').get();
      targets = membersSnap.docs.map(d => d.data()?.email).filter((e: any) => typeof e === 'string');
    }
    const unique = Array.from(new Set(targets));

    const publicBase =
      process.env.PUBLIC_BASE_URL ||
      process.env.API_BASE_URL ||
      process.env.BACKEND_BASE_URL ||
      'http://localhost:5000';

    const codeUrl = `${publicBase}/groups/${groupId}/codes/${code}`;
    for (const to of unique) {
      try {
        await sendEmail(
          to,
          'Your Howdy Group Code',
          `Here is a Howdy group code: ${code}\n\nLearn more: ${codeUrl}`,
          `<p>Your Howdy group code is: <strong>${code}</strong></p><p>Learn more: <a href="${codeUrl}">${codeUrl}</a></p>`
        );
      } catch (e) {
        console.warn('⚠️ Failed to email code to', to, e);
      }
    }
    return res.status(200).json({ ok: true, sent: unique.length });
  } catch (e) {
    console.error('❌ email code failed', e);
    return res.status(500).json({ error: 'Failed to email code' });
  }
});

// POST /groups/invite/resend { groupId, email }
groupsRouter.post('/invite/resend', async (req, res) => {
  const uid = (req as any).uid as string;
  const groupId = String(req.body?.groupId || '');
  const email = String(req.body?.email || '');
  if (!groupId || !email) return res.status(400).json({ error: 'Missing groupId or email' });

  try {
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const role = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const snap = await db.collection('group_invites')
      .where('groupId', '==', groupId)
      .where('email', '==', email)
      .orderBy('createdAt', 'desc')
      .limit(1)
      .get();
    if (snap.empty) return res.status(404).json({ error: 'No invite found' });
    const inviteRef = snap.docs[0].ref;
    const invite = snap.docs[0].data() as any;

    const last = invite.lastSentAt || invite.createdAt || 0;
    if (Date.now() - last < 60_000) {
      const waitMs = 60_000 - (Date.now() - last);
      return res.status(429).json({ error: 'Please wait before resending', retryAfterMs: waitMs });
    }

    const token = inviteRef.id;

    const publicBase = resolvePublicBase();

    const appDeepLink = `howdy://accept-invite?token=${token}${invite.role ? `&role=${encodeURIComponent(invite.role)}` : ''}`;
    const webFallback = `${publicBase}/groups/invite/${token}${invite.role ? `?role=${encodeURIComponent(invite.role)}` : ''}`;

    // Load group to include name in email
    let groupName = 'Howdy Group';
    try {
      const gdoc = await db.collection('groups').doc(invite.groupId).get();
      groupName = (gdoc.data()?.name as string) || groupName;
    } catch {}

    try {
      await sendEmail(
        email,
        `You're invited to ${groupName} on Howdy (resend)`,
        `You're invited to ${groupName} on Howdy.\n\nJoin on the web: ${webFallback}\nApp link: ${appDeepLink}`,
        `<div style="font-family:system-ui,-apple-system,Segoe UI,Roboto,Inter,sans-serif;font-size:14px;color:#222;line-height:1.5">
          <p>You have been invited to join <strong>${groupName}</strong> on Howdy.</p>
          <p>
            <a href="${webFallback}" style="
              display:inline-block;
              background:#d37f1c;
              color:#fff;
              padding:12px 16px;
              border-radius:8px;
              text-decoration:none;
              font-weight:600;">Accept invite</a>
          </p>
          <p>You can also <a href="${webFallback}">join on the web</a>.</p>
          <p style="color:#666;font-size:13px">If supported, this direct app link may also work:<br/><code>${appDeepLink}</code></p>
        </div>`
      );
    } catch (e) {
      console.warn('⚠️ Failed to resend invite email', e);
    }

    await inviteRef.set({ lastSentAt: Date.now() }, { merge: true });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ resend invite failed', e);
    return res.status(500).json({ error: 'Failed to resend invite' });
  }
});

// POST /groups/invite/accept { token } (auth required)
groupsRouter.post('/invite/accept', async (req, res) => {
  const uid = (req as any).uid as string;
  const token = String(req.body?.token || '');
  if (!token) return res.status(400).json({ error: 'Missing token' });

  try {
    const inviteDoc = await db.collection('group_invites').doc(token).get();
    if (!inviteDoc.exists) return res.status(400).json({ error: 'Invalid token' });
    const invite = inviteDoc.data() as any;
    if (Date.now() > (invite.expiresAt || 0)) return res.status(400).json({ error: 'Invite expired' });

    const { groupId, email, role } = invite;

    const userDoc = await db.collection('users').doc(uid).get();
    const userEmail = userDoc.data()?.email;
    const memberDocId = userEmail || email;

    const memberRef = db.collection('groups').doc(groupId).collection('members').doc(memberDocId);
    await memberRef.set({
      uid,
      email: userEmail || email,
      role: role || 'member',
      status: 'active',
      acceptedAt: Date.now(),
    }, { merge: true });

    // Ensure guardian
    let guardianUid: string | null = null;
    let guardianEmail: string | null = null;
    const currentMember = await memberRef.get();
    if (currentMember.exists) {
      const d: any = currentMember.data();
      guardianUid = d?.guardianUid || null;
      guardianEmail = d?.guardianEmail || null;
    }
    if (!guardianUid) {
      guardianUid = invite.invitedBy || null;
      if (guardianUid) {
        try {
          const invUser = await db.collection('users').doc(guardianUid).get();
          guardianEmail = (invUser.data()?.email as string) || guardianEmail;
        } catch {}
      }
      await memberRef.set({ guardianUid, guardianEmail }, { merge: true });
    }

    const metaUpdate: any = {
      primaryGroupId: groupId,
      guardianUid: guardianUid || undefined,
      guardianEmail: guardianEmail || undefined,
    };
    if (role === 'member') {
      metaUpdate.accountType = 'member';
    }
    await db.collection('user_metadata').doc(uid).set(metaUpdate, { merge: true });

    await inviteDoc.ref.delete(); // consume invite

    await db.collection('user_metadata').doc(uid).set({ primaryGroupId: groupId }, { merge: true });

    return res.status(200).json({ ok: true, groupId });
  } catch (e) {
    console.error('❌ accept invite failed', e);
    return res.status(500).json({ error: 'Failed to accept invite' });
  }
});
