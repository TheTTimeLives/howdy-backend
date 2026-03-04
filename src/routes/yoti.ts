import express from 'express';
import * as fs from 'fs';
import { db } from '../firebase';
import { encryptString } from '../utils/pii';
import { verifyJwt } from '../verifyJwt';
import { logAuditEvent } from '../utils/audit';

import {
  IDVClient,
  SessionSpecificationBuilder,
  SdkConfigBuilder,
  RequestedDocumentAuthenticityCheckBuilder,
  RequestedLivenessCheckBuilder,
  RequestedFaceMatchCheckBuilder,
  RequestedTextExtractionTaskBuilder,
  NotificationConfigBuilder,
} from 'yoti';

// ✅ CommonJS require to bypass missing types
const { token_sort_ratio } = require('fuzzball');
const {
  SandboxIDVClientBuilder,
  SandboxRecommendationBuilder,
  SandboxBreakdownBuilder,
  SandboxDocumentAuthenticityCheckBuilder,
  SandboxDocumentTextDataCheckBuilder,
  SandboxZoomLivenessCheckBuilder,
  SandboxDocumentFaceMatchCheckBuilder,
  SandboxDocumentTextDataExtractionTaskBuilder,
  SandboxCheckReportsBuilder,
  SandboxTaskResultsBuilder,
  SandboxResponseConfigBuilder,
} = require('@getyoti/sdk-sandbox');



// 🔀 Environment Toggle
const isSandbox = process.env.YOTI_ENV === 'sandbox';

// 🔑 Dynamic Configs
const YOTI_CLIENT_SDK_ID = process.env.YOTI_CLIENT_SDK_ID!;
const YOTI_KEY_FILE = process.env.YOTI_KEY_FILE!;
const YOTI_KEY = fs.readFileSync(YOTI_KEY_FILE, 'utf8');
const YOTI_SUCCESS_URL = process.env.YOTI_SUCCESS_URL!;
const YOTI_ERROR_URL = process.env.YOTI_ERROR_URL!;
const YOTI_WEBHOOK_AUTH = process.env.YOTI_WEBHOOK_AUTH || 'howdy:yoti';
const PUBLIC_BASE_URL = process.env.PUBLIC_BASE_URL;
const YOTI_WEBHOOK_URL =
  process.env.YOTI_WEBHOOK_URL ||
  (PUBLIC_BASE_URL ? `${PUBLIC_BASE_URL}/yoti/webhook` : undefined);

const ENFORCE_ID_COLLISION_REVIEW =
  String(process.env.ENFORCE_ID_COLLISION_REVIEW ?? 'true').toLowerCase() === 'true';

/** Dev only: create identity_profiles whenever we can extract identity,
 *  even if user ends up processing/denied. Useful for testing collision flow without full approval. */
const DEV_CREATE_IDENTITY_ON_ANY_VERIFICATION =
  String(process.env.DEV_CREATE_IDENTITY_ON_ANY_VERIFICATION ?? 'false').toLowerCase() === 'true';

if (isSandbox) {
  // 🔁 Redirect all IDVClient traffic to sandbox API
  process.env.YOTI_IDV_API_URL = 'https://api.yoti.com/sandbox/idverify/v1';
  console.log('🧪 Using Yoti SANDBOX environment');
} else {
  console.log('🚀 Using Yoti PRODUCTION environment');
}

// 🛠️ Initialize Yoti IDVClient (uses API URL from env var internally)
const idvClient = new IDVClient(YOTI_CLIENT_SDK_ID, YOTI_KEY, {
  apiUrl: isSandbox
    ? 'https://api.yoti.com/sandbox/idverify/v1'
    : 'https://api.yoti.com/idverify/v1',
});


// 🔐 Secure Router
export const yotiRouter = express.Router();
yotiRouter.use((req, res, next) => {
  // Webhook uses Basic auth from Yoti, not JWT
  if (req.path === '/webhook' && req.method === 'POST') return next();
  return verifyJwt(req, res, next);
});

// COMMENTED OUT: Custom deduplication logic (not currently in use)
// Waiting for Yoti's built-in identity tracking solution
// This function creates a hash from name+DOB and checks for duplicates in Firestore
// Uncomment the calls to this function when ready to enable our deduplication
async function checkIdentityDuplication(sessionResult: any, userId: string): Promise<{ isDuplicate: boolean; identityHash?: string }> {
  try {
    const textChecks = sessionResult.getIdDocumentTextDataChecks();
    if (textChecks.length === 0) {
      console.warn('⚠️ No ID document text checks found for deduplication');
      return { isDuplicate: false };
    }

    const check = textChecks[0];
    const fields = (check as any).getDocumentFields?.();

    if (!fields) {
      console.warn('⚠️ No document fields found');
      return { isDuplicate: false };
    }

    const fullName = fields.getField('full_name')?.getValue();
    const dob = fields.getField('date_of_birth')?.getValue();

    if (!fullName || !dob) {
      console.warn('⚠️ Missing identity fields (name or dob)');
      return { isDuplicate: false };
    }

    // Create unique identity hash using ONLY name + DOB
    // This prevents bypass via different document types (passport vs ID)
    const rawString = `${fullName}|${dob}`;
    const crypto = await import('crypto');
    const hash = crypto.createHash('sha256').update(rawString).digest('hex');

    // Check for existing identity (exclude current user)
    const existing = await db
      .collection('user_metadata')
      .where('identityHash', '==', hash)
      .get();

    const duplicateExists = !existing.empty && existing.docs.some(doc => doc.id !== userId);

    if (duplicateExists) {
      console.warn(`⚠️ Duplicate identity detected: ${fullName}, hash: ${hash.substring(0, 16)}...`);
      return { isDuplicate: true, identityHash: hash };
    }

    return { isDuplicate: false, identityHash: hash };
  } catch (err) {
    console.error('❌ Deduplication check failed:', err);
    return { isDuplicate: false };
  }
}

// --- Identity collision flow (name+DOB block keys) ---
// Extracts full_name and date_of_birth from Yoti session result.
// Sandbox and production must return the same structure per Yoti docs:
// https://developers.yoti.com/identity-verification/retrieve-userdata
function extractIdentity(sessionResult: any): { fullNameNorm: string; dobNorm: string; first: string; last: string } | null {
  const parse = (fullName: string, dob: string) => {
    if (!fullName || !dob || typeof fullName !== 'string' || typeof dob !== 'string') return null;
    const fullNameNorm = fullName.trim().toLowerCase().replace(/\s+/g, ' ');
    const dobNorm = dob.replace(/\D/g, '').slice(0, 8) || dob;
    const parts = fullName.trim().split(/\s+/);
    const first = parts[0] || '';
    const last = parts.length > 1 ? parts.slice(1).join(' ') : '';
    return { fullNameNorm, dobNorm, first, last };
  };

  const tryFields = (fields: any): ReturnType<typeof parse> => {
    if (!fields) return null;
    const fullName = typeof fields.getField === 'function'
      ? fields.getField('full_name')?.getValue?.()
      : fields.full_name;
    const dob = typeof fields.getField === 'function'
      ? fields.getField('date_of_birth')?.getValue?.()
      : fields.date_of_birth;
    return parse(fullName, dob);
  };

  try {
    // Path 1: getResources().getIdDocuments()[].getDocumentFields() — canonical IDV API
    const resources = sessionResult.getResources?.();
    const idDocs = resources?.getIdDocuments?.();
    if (idDocs?.length > 0) {
      const doc = idDocs[0];
      const docFields = doc.getDocumentFields?.();
      const out = tryFields(docFields);
      if (out) return out;
    }

    // Path 2: getTextDataChecks()[].getDocumentFields() — IDV checks API
    const textDataChecks = sessionResult.getTextDataChecks?.();
    if (textDataChecks?.length > 0) {
      const fields = (textDataChecks[0] as any).getDocumentFields?.();
      const out = tryFields(fields);
      if (out) return out;
    }

    // Path 3: getIdDocumentTextDataChecks() — Doc Scan / legacy
    const textChecks = sessionResult.getIdDocumentTextDataChecks?.();
    if (textChecks?.length > 0) {
      const fields = (textChecks[0] as any).getDocumentFields?.();
      const out = tryFields(fields);
      if (out) return out;
    }

    // Path 4: Raw JSON (e.g. if SDK returns plain object or different shape)
    const json = JSON.stringify(sessionResult);
    const fullNameMatch = json.match(/"full_name"\s*:\s*"([^"]+)"/);
    const dobMatch = json.match(/"date_of_birth"\s*:\s*"([^"]+)"/);
    if (fullNameMatch && dobMatch) {
      const out = parse(fullNameMatch[1], dobMatch[1]);
      if (out) {
        console.log('[YOTI] extractIdentity: resolved via raw JSON scan');
        return out;
      }
    }
  } catch (e) {
    console.warn('[YOTI] extractIdentity error:', e);
  }

  // Log available methods when extraction fails (helps align sandbox with production)
  const methods = typeof sessionResult === 'object' && sessionResult !== null
    ? Object.getOwnPropertyNames(Object.getPrototypeOf(sessionResult)).filter((m: string) => m.startsWith('get'))
    : [];
  console.warn('[YOTI] extractIdentity: no identity found. Session methods:', methods.slice(0, 20).join(', '));
  return null;
}

/** Fuzzy similarity thresholds (0-100). Over 70% on both name and DOB → collision (processing, pending admin review). */
const NAME_SIMILARITY_THRESHOLD = 70;
const DOB_SIMILARITY_THRESHOLD = 70;

function evaluateChecks(sessionResult: any): { allChecksComplete: boolean; approved: boolean } {
  const checks = sessionResult.getChecks?.() ?? [];
  let allChecksComplete = true;
  let approved = true;
  for (const check of checks) {
    const recommendation = check.getReport?.()?.getRecommendation?.()?.getValue?.();
    if (!recommendation || recommendation === 'PENDING') {
      allChecksComplete = false;
      break;
    }
    if (recommendation !== 'APPROVE') approved = false;
  }
  return { allChecksComplete, approved };
}

async function upsertIdentityAndFindCollisions(
  userId: string,
  identity: { fullNameNorm: string; dobNorm: string; first: string; last: string }
): Promise<{ candidateUserIds: string[] }> {
  const now = Date.now();

  // Store plaintext (pending a better secure system). Enables fuzzy collision matching.
  await db.collection('identity_profiles').doc(userId).set(
    {
      userId,
      fullNameNorm: identity.fullNameNorm,
      dobNorm: identity.dobNorm,
      updatedAt: now,
      createdAt: now,
    },
    { merge: true }
  );

  // Fetch all identity profiles and fuzzy-compare name + DOB
  const snap = await db.collection('identity_profiles').get();
  const candidateUserIds = new Set<string>();
  for (const doc of snap.docs) {
    const otherUid = doc.id;
    if (otherUid === userId) continue;
    const data = doc.data() as { fullNameNorm?: string; dobNorm?: string };
    const otherName = String(data.fullNameNorm || '');
    const otherDob = String(data.dobNorm || '');
    if (!otherName || !otherDob) continue;

    const nameScore = token_sort_ratio(identity.fullNameNorm, otherName);
    const dobScore = token_sort_ratio(identity.dobNorm, otherDob);
    if (nameScore >= NAME_SIMILARITY_THRESHOLD && dobScore >= DOB_SIMILARITY_THRESHOLD) {
      candidateUserIds.add(otherUid);
    }
  }
  return { candidateUserIds: Array.from(candidateUserIds) };
}

async function createOrReuseCollisionCase(
  userId: string,
  identity: { fullNameNorm: string; dobNorm: string },
  candidateUserIds: string[]
): Promise<string> {
  const existing = await db
    .collection('identity_collision_cases')
    .where('userId', '==', userId)
    .where('status', '==', 'pending_review')
    .limit(1)
    .get();
  if (!existing.empty) return existing.docs[0].id;

  const now = Date.now();
  const ref = await db.collection('identity_collision_cases').add({
    userId,
    candidateUserIds,
    status: 'pending_review',
    collisionType: 'identity_fuzzy_match',
    fullNameNorm: identity.fullNameNorm,
    dobNorm: identity.dobNorm,
    createdAt: now,
    updatedAt: now,
  });

  await logAuditEvent({
    actorUid: null,
    actorType: 'system',
    action: 'collision_case_created',
    entityType: 'identity_collision_case',
    entityId: ref.id,
    metadata: { userId, candidateCount: candidateUserIds.length },
  });

  return ref.id;
}

async function processSessionResult(
  userId: string,
  sessionResult: any,
  source: 'status_poll' | 'webhook'
): Promise<string> {
  try {
    // Dev: create identity profile whenever we can extract identity, even if processing/denied
    if (DEV_CREATE_IDENTITY_ON_ANY_VERIFICATION) {
      let identity = extractIdentity(sessionResult);
      // Sandbox often doesn't return document fields in getSession — use fixed fake identity when extraction fails
      // (Fixed identity = all sandbox users collide, useful for testing collision flow)
      if (!identity && isSandbox) {
        identity = {
          fullNameNorm: 'jane test',
          dobNorm: '19900101',
          first: 'jane',
          last: 'test',
        };
        console.log(`[DEV] Sandbox: no identity in session, using fake identity for ${userId}`);
      }
      if (identity) {
        try {
          const { candidateUserIds } = await upsertIdentityAndFindCollisions(userId, identity);
          console.log(`[DEV] Created identity profile for ${userId}, candidateUserIds=[${candidateUserIds.join(', ')}] (count=${candidateUserIds.length})`);
          // Also run collision flow when DEV creates identity (main flow won't reach it if extractIdentity returns null)
          if (candidateUserIds.length > 0) {
            const caseId = await createOrReuseCollisionCase(userId, identity, candidateUserIds);
            if (ENFORCE_ID_COLLISION_REVIEW) {
              // Stay in processing — denial only when admin explicitly denies. User can proceed with onboarding.
              await db.collection('user_metadata').doc(userId).set(
                {
                  verificationStatus: 'processing',
                  identityCollisionCaseId: caseId,
                  identityCollisionBypassed: false,
                },
                { merge: true }
              );
              await logAuditEvent({
                actorUid: null,
                actorType: 'system',
                action: 'verification_collision_pending_review',
                entityType: 'user_metadata',
                entityId: userId,
                metadata: { source, reason: 'collision_pending_review', caseId, candidateCount: candidateUserIds.length },
              });
              console.log(`[DEV] Collision detected for ${userId} → processing (case ${caseId}, pending admin review)`);
              return 'processing';
            }
          }
        } catch (e) {
          console.warn('[DEV] Failed to create identity profile:', e);
        }
      }
    }

    const { allChecksComplete, approved } = evaluateChecks(sessionResult);
    if (!allChecksComplete) {
      await db.collection('user_metadata').doc(userId).set(
        { verificationStatus: 'processing' },
        { merge: true }
      );
      return 'processing';
    }

    if (!approved) {
      await db.collection('user_metadata').doc(userId).set(
        { verificationStatus: 'denied' },
        { merge: true }
      );
      await logAuditEvent({
        actorUid: null,
        actorType: 'system',
        action: 'verification_denied',
        entityType: 'user_metadata',
        entityId: userId,
        metadata: { source, reason: 'yoti_denied' },
      });
      return 'denied';
    }

    const identity = extractIdentity(sessionResult);
    if (!identity) {
      await db.collection('user_metadata').doc(userId).set(
        { verificationStatus: 'processing' },
        { merge: true }
      );
      return 'processing';
    }

    const { candidateUserIds } = await upsertIdentityAndFindCollisions(userId, identity);

    if (candidateUserIds.length > 0) {
      const caseId = await createOrReuseCollisionCase(userId, identity, candidateUserIds);
      if (ENFORCE_ID_COLLISION_REVIEW) {
        // Stay in processing — denial only when admin explicitly denies. User can proceed with onboarding.
        await db.collection('user_metadata').doc(userId).set(
          {
            verificationStatus: 'processing',
            identityCollisionCaseId: caseId,
            identityCollisionBypassed: false,
          },
          { merge: true }
        );
        await logAuditEvent({
          actorUid: null,
          actorType: 'system',
          action: 'verification_collision_pending_review',
          entityType: 'user_metadata',
          entityId: userId,
          metadata: { source, reason: 'collision_pending_review', caseId, candidateCount: candidateUserIds.length },
        });
        return 'processing';
      }

      await db.collection('user_metadata').doc(userId).set(
        {
          verificationStatus: 'processing',
          identityCollisionCaseId: caseId,
          identityCollisionBypassed: true,
        },
        { merge: true }
      );
      await logAuditEvent({
        actorUid: null,
        actorType: 'system',
        action: 'verification_collision_bypassed',
        entityType: 'user_metadata',
        entityId: userId,
        metadata: { source, reason: 'collision_bypassed', caseId, candidateCount: candidateUserIds.length },
      });
      return 'processing';
    }

    await db.collection('user_metadata').doc(userId).set(
      {
        verificationStatus: 'approved',
        identityCollisionCaseId: null,
      },
      { merge: true }
    );
    await logAuditEvent({
      actorUid: null,
      actorType: 'system',
      action: 'verification_approved',
      entityType: 'user_metadata',
      entityId: userId,
      metadata: { source, reason: 'yoti_approved' },
    });
    return 'approved';
  } catch (err) {
    console.error('❌ Failed to process identity collision flow:', err);
    return 'processing';
  }
}

// POST /yoti/session
yotiRouter.post('/session', async (req, res) => {
  const uid = String((req as any).uid ?? '');

  console.log(`📦 Creating Yoti session for uid: ${uid}`);
console.log(`🌍 Environment: ${isSandbox ? 'sandbox' : 'production'}`);

  try {
    const sdkConfig = new SdkConfigBuilder()
      .withAllowsCameraAndUpload()
      .withSuccessUrl(YOTI_SUCCESS_URL)
      .withErrorUrl(YOTI_ERROR_URL)
      .withAllowHandoff(true)
      .build();

    // ✅ Build webhook notification config when public URL is available
    let notificationConfig: any | undefined;
    if (YOTI_WEBHOOK_URL) {
      notificationConfig = new NotificationConfigBuilder()
        .withEndpoint(YOTI_WEBHOOK_URL)
        .withAuthTypeBasic()
        .withAuthToken(YOTI_WEBHOOK_AUTH)
        .forSessionCompletion()
        .build();
      console.log(`🔔 Yoti webhook configured: ${YOTI_WEBHOOK_URL}`);
    } else {
      console.warn('⚠️ Yoti webhook NOT configured (no PUBLIC_BASE_URL or YOTI_WEBHOOK_URL). Status will rely on polling.');
    }

    // Build session spec; attach notifications only if available
    let specBuilder = new SessionSpecificationBuilder()
      .withClientSessionTokenTtl(600)
      .withUserTrackingId(uid)
      .withRequestedCheck(new RequestedDocumentAuthenticityCheckBuilder().build())
      .withRequestedCheck(new RequestedLivenessCheckBuilder().forStaticLiveness().withMaxRetries(3).build())
      .withRequestedCheck(new RequestedFaceMatchCheckBuilder().withManualCheckFallback().build())
      .withRequestedTask(new RequestedTextExtractionTaskBuilder().withManualCheckFallback().build())
      .withSdkConfig(sdkConfig);

    if (notificationConfig) {
      specBuilder = specBuilder.withNotifications(notificationConfig);
    }

    const sessionSpec = specBuilder.build();

    const sessionResult = await idvClient.createSession(sessionSpec);
    const sessionId = sessionResult.getSessionId();
    const clientSessionToken = sessionResult.getClientSessionToken();

    // Save to Firestore
    await db.collection('user_metadata').doc(uid).set({
      yotiSessionId: sessionId,
      yotiToken: clientSessionToken,
      verificationStatus: 'verify-started',  // User is about to/in Yoti flow
    }, { merge: true });

    // 🧪 Inject test result if sandbox
    if (isSandbox) {
      const sandboxClient = new SandboxIDVClientBuilder()
        .withClientSdkId(YOTI_CLIENT_SDK_ID)
        .withPemString(YOTI_KEY)
        .build();

      const docCheck = new SandboxDocumentAuthenticityCheckBuilder()
        .withRecommendation(new SandboxRecommendationBuilder().withValue('APPROVE').build())
        .withBreakdown(new SandboxBreakdownBuilder().withSubCheck('security_features').withResult('PASS').build())
        .build();

      const faceCheck = new SandboxDocumentFaceMatchCheckBuilder()
        .withRecommendation(new SandboxRecommendationBuilder().withValue('APPROVE').build())
        .withBreakdown(new SandboxBreakdownBuilder().withSubCheck('ai_face_match').withResult('PASS').build())
        .build();

      const livenessCheck = new SandboxZoomLivenessCheckBuilder()
        .withRecommendation(new SandboxRecommendationBuilder().withValue('APPROVE').build())
        .withBreakdown(new SandboxBreakdownBuilder().withSubCheck('liveness').withResult('PASS').build())
        .build();

      const textCheck = new SandboxDocumentTextDataCheckBuilder()
        .withRecommendation(new SandboxRecommendationBuilder().withValue('APPROVE').build())
        .withBreakdown(new SandboxBreakdownBuilder().withSubCheck('text_data_readable').withResult('PASS').build())
        .withDocumentFields({
          full_name: 'Jane Test',
          nationality: 'USA',
          date_of_birth: '1990-01-01',
          document_number: 'ABC123456',
        })
        .build();

      const textExtraction = new SandboxDocumentTextDataExtractionTaskBuilder()
        .withDocumentFields({
          full_name: 'Jane Test',
          nationality: 'USA',
          date_of_birth: '1990-01-01',
          document_number: 'ABC123456',
        })
        .build();

      const responseConfig = new SandboxResponseConfigBuilder()
        .withCheckReports(
          new SandboxCheckReportsBuilder()
            .withDocumentAuthenticityCheck(docCheck)
            .withDocumentFaceMatchCheck(faceCheck)
            .withLivenessCheck(livenessCheck)
            .withDocumentTextDataCheck(textCheck)
            .build()
        )
        .withTaskResults(
          new SandboxTaskResultsBuilder()
            .withDocumentTextDataExtractionTask(textExtraction)
            .build()
        )
        .build();

      await sandboxClient.configureSessionResponse(sessionId, responseConfig);
    }

    res.status(200).json({ sessionId, clientSessionToken, isSandbox, });
  } catch (err) {
    console.error('❌ Failed to create Yoti session:', err);
    res.status(500).json({ error: 'Could not create Yoti session' });
  }
});


// GET /yoti/status
yotiRouter.get('/status', async (req, res) => {
  const uid = (req as any).uid;

  try {
    const doc = await db.collection('user_metadata').doc(uid).get();
    const data = doc.data();
    let status = data?.verificationStatus ?? 'awaiting';
    
    // Fallback: if status is still 'verify-started' or 'processing' and we have a sessionId, actively poll Yoti
    if ((status === 'verify-started' || status === 'processing') && data?.yotiSessionId) {
      try {
        const sessionId = data.yotiSessionId;
        const sessionResult = await idvClient.getSession(sessionId);
        status = await processSessionResult(uid, sessionResult, 'status_poll');
        console.log(`[YOTI_STATUS] Poll result: uid=${uid} → ${status}`);
      } catch (pollErr) {
        console.warn('[YOTI_STATUS] Failed to poll session:', pollErr);
        // Keep existing status on error
      }
    }
    
    res.status(200).json({ status });
  } catch (e) {
    console.error('❌ Failed to fetch Yoti status:', e);
    res.status(500).json({ error: 'Failed to check verification status' });
  }
});

// POST /yoti/webhook
yotiRouter.post('/webhook', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const expectedAuth = 'Basic ' + Buffer.from(YOTI_WEBHOOK_AUTH).toString('base64');

  if (authHeader !== expectedAuth) {
    console.warn('❌ Unauthorized webhook attempt');
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { session_id, topic } = req.body;
  console.log(`📩 Webhook received: session_id=${session_id}, topic=${topic}`);

  if (!session_id || !topic) {
    return res.status(400).json({ error: 'Missing session_id or topic' });
  }

  try {
    if (topic === 'session_completion') {
      const sessionResult = await idvClient.getSession(session_id);
      const userId = sessionResult.getUserTrackingId();

      if (!userId) {
        console.warn('⚠️ No userTrackingId found in session');
        return res.status(200).json({ ok: true });
      }

      const finalStatus = await processSessionResult(String(userId), sessionResult, 'webhook');
      console.log(`📩 Webhook: Session ${session_id} → ${finalStatus}`);

      // Store encrypted first/last name on users collection when available (best-effort parsing)
      try {
        const identity = extractIdentity(sessionResult);
        if (identity && (identity.first || identity.last)) {
          const firstEnc = identity.first ? encryptString(identity.first) : null;
          const lastEnc = identity.last ? encryptString(identity.last) : null;
          if (firstEnc || lastEnc) {
            await db.collection('users').doc(userId).set({
              pii: {
                ...(firstEnc ? { firstNameEnc: firstEnc } : {}),
                ...(lastEnc ? { lastNameEnc: lastEnc } : {}),
                piiVersion: 1,
              },
            }, { merge: true });
          }
        }
      } catch (e) {
        console.warn('⚠️ Failed to extract/store PII from Yoti result:', e);
      }

      return res.status(200).json({ ok: true });
    }

    console.log(`ℹ️ Ignoring non-session_completion topic: ${topic}`);
    res.status(200).json({ ignored: true });
  } catch (err) {
    console.error('❌ Webhook handling failed:', err);
    res.status(500).json({ error: 'Webhook failed' });
  }
});
