import express from 'express';
import * as fs from 'fs';
import crypto from 'crypto';
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
  String(process.env.ENFORCE_ID_COLLISION_REVIEW ?? 'true').toLowerCase() ===
  'true';

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
yotiRouter.use(verifyJwt);

function normalizeName(value: string): string {
  return value
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-zA-Z\s'-]/g, ' ')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function normalizeDob(value: string): string | null {
  const v = String(value || '').trim();
  if (!v) return null;

  if (/^\d{4}-\d{2}-\d{2}$/.test(v)) return v;

  const m = v.match(/^(\d{1,2})[/-](\d{1,2})[/-](\d{2,4})$/);
  if (!m) return null;
  const month = Number(m[1]);
  const day = Number(m[2]);
  const yy = Number(m[3]);
  const year = yy < 100 ? (yy >= 50 ? 1900 + yy : 2000 + yy) : yy;
  if (month < 1 || month > 12 || day < 1 || day > 31 || year < 1900) return null;
  const mm = String(month).padStart(2, '0');
  const dd = String(day).padStart(2, '0');
  return `${year}-${mm}-${dd}`;
}

function extractIdentity(sessionResult: any): { fullNameNorm: string; dobNorm: string; first: string; last: string } | null {
  const textChecks = sessionResult.getIdDocumentTextDataChecks?.() || [];
  if (!Array.isArray(textChecks) || textChecks.length === 0) return null;

  const check = textChecks[0];
  const fields = (check as any).getDocumentFields?.();
  if (!fields) return null;

  const fullNameRaw = String(fields.getField('full_name')?.getValue?.() || '').trim();
  const dobRaw = String(fields.getField('date_of_birth')?.getValue?.() || '').trim();
  if (!fullNameRaw || !dobRaw) return null;

  const fullNameNorm = normalizeName(fullNameRaw);
  const dobNorm = normalizeDob(dobRaw);
  if (!fullNameNorm || !dobNorm) return null;

  const parts = fullNameNorm.split(' ').filter(Boolean);
  const first = parts[0] || '';
  const last = parts[parts.length - 1] || '';
  if (!first || !last) return null;

  return { fullNameNorm, dobNorm, first, last };
}

function makeBlockHashes(identity: { fullNameNorm: string; dobNorm: string; first: string; last: string }): string[] {
  const firstInitial = identity.first.charAt(0);
  const keys = [
    `dob=${identity.dobNorm}|first=${identity.first}|last=${identity.last}`,
    `dob=${identity.dobNorm}|last=${identity.last}|fi=${firstInitial}`,
    `dob=${identity.dobNorm}|name=${identity.fullNameNorm}`,
  ];
  return keys.map((key) => crypto.createHash('sha256').update(key).digest('hex'));
}

function evaluateChecks(sessionResult: any): { allChecksComplete: boolean; approved: boolean } {
  const checks = sessionResult.getChecks?.() || [];
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

async function upsertIdentityAndFindCollisions(userId: string, identity: { fullNameNorm: string; dobNorm: string; first: string; last: string }) {
  const now = Date.now();
  const hashes = makeBlockHashes(identity);

  await db.collection('identity_profiles').doc(userId).set(
    {
      userId,
      fullNameNormEnc: encryptString(identity.fullNameNorm),
      dobNormEnc: encryptString(identity.dobNorm),
      fullNameNormHash: crypto.createHash('sha256').update(identity.fullNameNorm).digest('hex'),
      dobNormHash: crypto.createHash('sha256').update(identity.dobNorm).digest('hex'),
      updatedAt: now,
      createdAt: now,
    },
    { merge: true }
  );

  for (let i = 0; i < hashes.length; i++) {
    const keyHash = hashes[i];
    const docId = `${userId}_${i}_${keyHash.slice(0, 24)}`;
    await db.collection('identity_block_keys').doc(docId).set(
      { userId, keyHash, createdAt: now, updatedAt: now },
      { merge: true }
    );
  }

  const candidateUserIds = new Set<string>();
  for (const keyHash of hashes) {
    const snap = await db
      .collection('identity_block_keys')
      .where('keyHash', '==', keyHash)
      .limit(30)
      .get();
    for (const doc of snap.docs) {
      const matchUid = String(doc.data().userId || '');
      if (matchUid && matchUid !== userId) candidateUserIds.add(matchUid);
    }
  }
  return { hashes, candidateUserIds: Array.from(candidateUserIds) };
}

async function createOrReuseCollisionCase(userId: string, identity: { fullNameNorm: string; dobNorm: string }, candidateUserIds: string[]) {
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
    collisionType: 'identity_block_key',
    fullNameNormEnc: encryptString(identity.fullNameNorm),
    dobNormEnc: encryptString(identity.dobNorm),
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

async function processSessionResult(userId: string, sessionResult: any, source: 'status_poll' | 'webhook') {
  try {
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
        metadata: { source },
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
        await db.collection('user_metadata').doc(userId).set(
          {
            verificationStatus: 'manual-review',
            identityCollisionCaseId: caseId,
            identityCollisionBypassed: false,
          },
          { merge: true }
        );
        await logAuditEvent({
          actorUid: null,
          actorType: 'system',
          action: 'verification_manual_review',
          entityType: 'user_metadata',
          entityId: userId,
          metadata: { source, caseId, candidateCount: candidateUserIds.length },
        });
        return 'manual-review';
      }

      // Dev/test bypass mode: keep user flow unblocked, but still create and audit cases.
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
        metadata: { source, caseId, candidateCount: candidateUserIds.length },
      });
      return 'processing';
    }

    await db.collection('user_metadata').doc(userId).set(
      {
        verificationStatus: 'processing',
        identityCollisionCaseId: null,
      },
      { merge: true }
    );
    return 'processing';
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
        return res.status(200).json({ ignored: true });
      }

      // Log all available Yoti identifiers for debugging
      console.log('📋 [YOTI] Session Result Properties:', {
        sessionId: sessionResult.getSessionId?.(),
        userTrackingId: sessionResult.getUserTrackingId?.(),
        // Check if Yoti provides any of these (may not exist):
        subjectId: (sessionResult as any).getSubjectId?.(),
        deviceId: (sessionResult as any).getDeviceId?.(),
        identityId: (sessionResult as any).getIdentityId?.(),
        // Log method names to see what's available:
        availableMethods: Object.getOwnPropertyNames(Object.getPrototypeOf(sessionResult))
          .filter(name => name.startsWith('get'))
      });

      const finalStatus = await processSessionResult(String(userId), sessionResult, 'webhook');
      console.log(`📩 Webhook: Session ${session_id} → ${finalStatus}`);

      if (userId) {
        // Store encrypted first/last name on users collection when available (best-effort parsing)
        try {
          const textChecks = sessionResult.getIdDocumentTextDataChecks();
          if (textChecks.length > 0) {
            const check = textChecks[0];
            const fields = (check as any).getDocumentFields?.();
            let fullName: string | undefined;
            if (fields) fullName = fields.getField('full_name')?.getValue();
            if (fullName && typeof fullName === 'string') {
              const parts = fullName.trim().split(/\s+/);
              const first = parts[0] || '';
              const last = parts.length > 1 ? parts.slice(1).join(' ') : '';
              const firstEnc = first ? encryptString(first) : null;
              const lastEnc = last ? encryptString(last) : null;
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
          }
        } catch (e) {
          console.warn('⚠️ Failed to extract/store PII from Yoti result:', e);
        }

        console.log(`✅ Updated verification status for user ${userId}: ${finalStatus}`);
      } else {
        console.warn('⚠️ No userTrackingId found in session');
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
