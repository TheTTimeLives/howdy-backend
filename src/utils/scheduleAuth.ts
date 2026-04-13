import { db } from '../firebase';

/**
 * Whether [requesterUid] may read calendar data (availability, events, connections)
 * as [participantUid] (self, confirmed connection, or staff in same group as member).
 */
export async function canViewScheduleFor(
  requesterUid: string,
  participantUid: string,
): Promise<boolean> {
  if (!requesterUid || !participantUid) return false;
  if (requesterUid === participantUid) return true;

  const forward = await db
    .collection('connections')
    .doc(requesterUid)
    .collection('confirmed')
    .doc(participantUid)
    .get();
  if (forward.exists) return true;

  const backward = await db
    .collection('connections')
    .doc(participantUid)
    .collection('confirmed')
    .doc(requesterUid)
    .get();
  if (backward.exists) return true;

  return staffSharesGroupWithMember(requesterUid, participantUid);
}

/**
 * Who may create/delete availability documents under schedules/{ownerUid}/availability:
 * the owner, or org/carer staff for a member in their group (not merely a connection).
 */
export async function canManageAvailabilityFor(
  requesterUid: string,
  ownerUid: string,
): Promise<boolean> {
  if (!requesterUid || !ownerUid) return false;
  if (requesterUid === ownerUid) return true;
  return staffSharesGroupWithMember(requesterUid, ownerUid);
}

async function staffSharesGroupWithMember(
  staffUid: string,
  memberUid: string,
): Promise<boolean> {
  let staffSnap;
  try {
    staffSnap = await db.collectionGroup('members').where('uid', '==', staffUid).limit(50).get();
  } catch {
    return false;
  }

  for (const doc of staffSnap.docs) {
    const role = String((doc.data() as any)?.role || 'member');
    if (role === 'member') continue;

    const pathParts = doc.ref.path.split('/');
    const groupId = pathParts[1];
    if (!groupId) continue;

    const byUid = await db
      .collection('groups')
      .doc(groupId)
      .collection('members')
      .where('uid', '==', memberUid)
      .limit(3)
      .get();
    if (!byUid.empty) return true;

    const byDoc = await db.collection('groups').doc(groupId).collection('members').doc(memberUid).get();
    if (byDoc.exists) {
      const d = byDoc.data() as any;
      if (d?.uid === memberUid || byDoc.id === memberUid) return true;
    }
  }
  return false;
}
