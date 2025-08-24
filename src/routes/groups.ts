import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';
import crypto from 'crypto';
import { sendEmail } from '../utils/email';

export const groupsRouter = express.Router();
groupsRouter.use(verifyJwt);

// Note: We do not enforce Yoti approval here; usage gating happens elsewhere.

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
      const member = await doc.ref.collection('members').doc(uid).get();
      if (member.exists) {
        const data = doc.data();
        groups.push({ id: doc.id, ...data, role: member.data()?.role || 'member' });
      }
    }
    return res.status(200).json({ groups });
  } catch (e) {
    console.error('❌ /groups/me failed', e);
    return res.status(500).json({ error: 'Failed to load groups' });
  }
});

// POST /groups/:groupId/members → add or update a member with role
groupsRouter.post('/:groupId/members', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId } = req.params;
  const { memberId, email, role, guardianUid: forcedGuardianUid } = req.body || {};
  if (!memberId && !email) return res.status(400).json({ error: 'memberId or email required' });
  if (!role) return res.status(400).json({ error: 'role required' });

  try {
    // simple authorization: only admins can add/update
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const adminRole = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(adminRole)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const targetId = memberId || email;
    const memberRef = db.collection('groups').doc(groupId).collection('members').doc(targetId);

    // Determine guardian: explicit guardianUid if provided and valid admin in this group; else default to acting admin
    let guardianUid: string | null = null;
    let guardianEmail: string | null = null;
    if (role === 'member') {
      let candidateUid: string | null = null;
      if (forcedGuardianUid && typeof forcedGuardianUid === 'string') {
        candidateUid = forcedGuardianUid;
      } else {
        candidateUid = uid; // fallback to acting admin
      }
      // Validate candidate is admin/super-admin of this group
      if (candidateUid) {
        const gdoc = await db
          .collection('groups')
          .doc(groupId)
          .collection('members')
          .doc(candidateUid)
          .get();
        const gRole = gdoc.data()?.role;
        if (gdoc.exists && ['super-admin', 'admin'].includes(gRole)) {
          guardianUid = candidateUid;
          try {
            const udoc = await db.collection('users').doc(candidateUid).get();
            guardianEmail = (udoc.data()?.email as string) || null;
          } catch {}
        } else {
          // If invalid guardian supplied, fall back to acting admin
          guardianUid = uid;
          try {
            const udoc = await db.collection('users').doc(uid).get();
            guardianEmail = (udoc.data()?.email as string) || null;
          } catch {}
        }
      }
    }

    // Note: Email-only invitations are stored as status 'pending' and are NOT effective members until accepted.
    const memberPayload: any = {
      uid: memberId || null,
      email: email || null,
      role, // intended role; only effective once status becomes 'active'
      addedAt: Date.now(),
      status: memberId ? 'active' : 'pending',
    };
    if (role === 'member') {
      memberPayload.guardianUid = guardianUid || uid;
      if (guardianEmail) memberPayload.guardianEmail = guardianEmail;
    }
    await memberRef.set(memberPayload, { merge: true });

    // If inviting by email, generate an invite token and send email
    if (email && !memberId) {
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

      const backendBase = process.env.BACKEND_BASE_URL || 'http://localhost:5000';
      const appDeepLink = `howdy://accept-invite?token=${token}`;
      const webFallback = `${backendBase}/groups/invite/${token}`;

      try {
        await sendEmail(
          email,
          'You have been invited to join a Howdy group',
          `You have been invited to join a Howdy group.\n\nOpen the app to accept: ${appDeepLink}\n\nIf the app does not open, use this web link: ${webFallback}`,
          `<p>You have been invited to join a <strong>Howdy</strong> group.</p>
           <p><strong>Accept via the app (preferred):</strong></p>
           <p><a href="${appDeepLink}">${appDeepLink}</a></p>
           <p style="margin-top:16px"><strong>Or accept on the web:</strong></p>
           <p><a href="${webFallback}">${webFallback}</a></p>`
        );
      } catch (e) {
        console.warn('⚠️ Failed to send invite email', e);
      }
    }

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
    const members = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    return res.status(200).json({ members });
  } catch (e) {
    console.error('❌ list members failed', e);
    return res.status(500).json({ error: 'Failed to list members' });
  }
});

// DELETE /groups/:groupId/members/:memberDocId → remove a member from group
groupsRouter.delete('/:groupId/members/:memberDocId', async (req, res) => {
  const uid = (req as any).uid as string;
  const { groupId, memberDocId } = req.params;
  try {
    const adminDoc = await db
      .collection('groups')
      .doc(groupId)
      .collection('members')
      .doc(uid)
      .get();
    const role = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    const memberRef = db
      .collection('groups')
      .doc(groupId)
      .collection('members')
      .doc(memberDocId);

    const memberDoc = await memberRef.get();
    if (!memberDoc.exists) {
      return res.status(404).json({ error: 'Member not found' });
    }

    await memberRef.delete();
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error('❌ remove member failed', e);
    return res.status(500).json({ error: 'Failed to remove member' });
  }
});

// --- Group Codes ---
// POST /groups/:groupId/codes → create a group code
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

// GET /groups/:groupId/codes → list codes
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

// POST /groups/:groupId/codes/:code/email { emails?: string[] } → email code to provided or all members
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
    const backendBase = process.env.BACKEND_BASE_URL || 'http://localhost:5000';
    const codeUrl = `${backendBase}/groups/${groupId}/codes/${code}`;
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
    // require admin-ish
    const adminDoc = await db.collection('groups').doc(groupId).collection('members').doc(uid).get();
    const role = adminDoc.data()?.role;
    if (!adminDoc.exists || !['super-admin', 'admin', 'team-lead'].includes(role)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }

    // find latest invite for this email
    const snap = await db.collection('group_invites')
      .where('groupId', '==', groupId)
      .where('email', '==', email)
      .orderBy('createdAt', 'desc')
      .limit(1)
      .get();
    if (snap.empty) return res.status(404).json({ error: 'No invite found' });
    const inviteRef = snap.docs[0].ref;
    const invite = snap.docs[0].data() as any;

    // cooldown: 60 seconds
    const last = invite.lastSentAt || invite.createdAt || 0;
    if (Date.now() - last < 60_000) {
      const waitMs = 60_000 - (Date.now() - last);
      return res.status(429).json({ error: 'Please wait before resending', retryAfterMs: waitMs });
    }

    // resend using stored token
    const token = inviteRef.id;
    const backendBase = process.env.BACKEND_BASE_URL || 'http://localhost:5000';
    const appDeepLink = `howdy://accept-invite?token=${token}`;
    const webFallback = `${backendBase}/groups/invite/${token}`;

    try {
      await sendEmail(
        email,
        'Your Howdy group invite (resend)',
        `Open the app to accept: ${appDeepLink}\n\nOr accept on the web: ${webFallback}`,
        `<p>You have been invited to join a <strong>Howdy</strong> group.</p>
         <p><strong>Accept via the app (preferred):</strong> <a href="${appDeepLink}">${appDeepLink}</a></p>
         <p><strong>Or accept on the web:</strong> <a href="${webFallback}">${webFallback}</a></p>`
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

    // Resolve user email; if matches, accept. If not, still allow linking but keep email saved.
    const userDoc = await db.collection('users').doc(uid).get();
    const userEmail = userDoc.data()?.email;

    const memberDocId = userEmail || email;
    const memberRef = db.collection('groups').doc(groupId).collection('members').doc(memberDocId);

    // On acceptance, we solidify membership: status becomes active, uid is attached. This is the moment they become a real member.
    await memberRef.set({
      uid,
      email: userEmail || email,
      role: role || 'member',
      status: 'active',
      acceptedAt: Date.now(),
    }, { merge: true });

    // Ensure guardian is set (prefer existing on member doc, else invitedBy)
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

    // Mirror to user_metadata so client can gate by guardian presence and member accountType
    const metaUpdate: any = {
      primaryGroupId: groupId,
      guardianUid: guardianUid || undefined,
      guardianEmail: guardianEmail || undefined,
    };
    if (role === 'member') {
      metaUpdate.accountType = 'member';
    }
    await db.collection('user_metadata').doc(uid).set(metaUpdate, { merge: true });

    // Mark invite consumed
    await inviteDoc.ref.delete();

    // Optionally set user's primaryGroupId if they don't have one
    await db.collection('user_metadata').doc(uid).set({
      primaryGroupId: groupId,
    }, { merge: true });

    return res.status(200).json({ ok: true, groupId });
  } catch (e) {
    console.error('❌ accept invite failed', e);
    return res.status(500).json({ error: 'Failed to accept invite' });
  }
});

// Simple web fallback for accepting invites
groupsRouter.get('/invite/:token', async (req, res) => {
  const token = req.params.token;
  const appDeepLink = `howdy://accept-invite?token=${token}`;
  res.setHeader('Content-Type', 'text/html');
  return res.status(200).send(`<!doctype html>
  <html lang="en">
    <head>
      <meta charset="utf-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <title>Accept invite • Howdy</title>
      <style>
        body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Inter, sans-serif; background:#f7f7f8; padding:24px; }
        .card { max-width:560px; margin: 40px auto; background:#fff; border:1px solid #e6e6eb; border-radius:12px; padding:20px; }
        a.btn { display:inline-block; padding:10px 14px; border-radius:10px; background:#1a73e8; color:#fff; font-weight:600; text-decoration:none; }
      </style>
    </head>
    <body>
      <div class="card">
        <h2>Accept your invite</h2>
        <p>Open the Howdy app to accept this invite:</p>
        <p><a class="btn" href="${appDeepLink}">Open the app</a></p>
        <p>If nothing happens, copy this link into a browser on your phone with the app installed.</p>
      </div>
    </body>
  </html>`);
});


