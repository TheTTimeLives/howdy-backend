import express from 'express';
import * as fs from 'fs';
import { db } from '../firebase';
import { encryptString } from '../utils/pii';
import { verifyJwt } from '../verifyJwt';

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
<<<<<<< HEAD
    const doc = await db.collection('user_metadata').doc(uid).get();
    const data = doc.data();
    let status = data?.verificationStatus ?? 'awaiting';
    
    // Fallback: if status is still 'verify-started' or 'processing' and we have a sessionId, actively poll Yoti
    if ((status === 'verify-started' || status === 'processing') && data?.yotiSessionId) {
      try {
        const sessionId = data.yotiSessionId;
        const sessionResult = await idvClient.getSession(sessionId);
        const checks = sessionResult.getChecks();
        
        // Check if all checks have completed
        let allChecksComplete = true;
        let approved = true;
        
        for (const check of checks) {
          const recommendation = check.getReport()?.getRecommendation()?.getValue();
          
          if (!recommendation || recommendation === 'PENDING') {
            // Check still processing
            allChecksComplete = false;
            break;
          }
          
          if (recommendation !== 'APPROVE') {
            approved = false;
          }
        }
        
        // Determine status and check for duplicates
        let newStatus: string;
        const updatePayload: Record<string, any> = {};
        
        if (!allChecksComplete) {
          newStatus = 'processing';
          console.log(`[YOTI_STATUS] Still processing: uid=${uid} - checks pending`);
        } else if (approved) {
          // COMMENTED OUT: Our custom deduplication logic - Yoti will provide their own solution
          // Uncomment below when ready to use our hash-based deduplication:
          // const dedupResult = await checkIdentityDuplication(sessionResult, uid);
          // if (dedupResult.isDuplicate) {
          //   newStatus = 'locked';
          //   updatePayload.identityDuplicate = true;
          //   console.log(`[YOTI_STATUS] 🔒 DUPLICATE DETECTED - Account locked: uid=${uid}`);
          // } else {
          //   newStatus = 'approved';
          //   if (dedupResult.identityHash) {
          //     updatePayload.identityHash = dedupResult.identityHash;
          //   }
          //   console.log(`[YOTI_STATUS] Approved with unique identity: uid=${uid}`);
          // }
          
          // Set to processing - users will proceed through onboarding
          newStatus = 'processing';
          console.log(`[YOTI_STATUS] Yoti checks passed → processing: uid=${uid}`);
        } else {
          newStatus = 'denied';
          console.log(`[YOTI_STATUS] Denied (checks failed): uid=${uid}`);
        }
        
        // Update database
        updatePayload.verificationStatus = newStatus;
        await db.collection('user_metadata').doc(uid).update(updatePayload);
        status = newStatus;
      } catch (pollErr) {
        console.warn('[YOTI_STATUS] Failed to poll session:', pollErr);
        // Keep existing status on error
      }
    }
    
=======
    const metaRef = db.collection('user_metadata').doc(uid);
    const doc = await metaRef.get();
    let status = doc.data()?.verificationStatus ?? 'awaiting';
    const sessionId = doc.data()?.yotiSessionId;

    // Proactive check if still processing and we have a session
    if (status === 'processing' && sessionId) {
      try {
        const sessionResult = await idvClient.getSession(sessionId);
        const state = sessionResult.getState();
        
        if (state === 'COMPLETED') {
          const checks = sessionResult.getChecks();
          let approved = true;
          for (const check of checks) {
            const recommendation = check.getReport()?.getRecommendation()?.getValue();
            if (recommendation !== 'APPROVE') {
              approved = false;
              break;
            }
          }
          status = approved ? 'approved' : 'denied';
          await metaRef.update({ verificationStatus: status });
          console.log(`[YOTI /status] Proactively updated status for ${uid} to ${status}`);
        }
      } catch (err) {
        console.warn(`[YOTI /status] Failed to fetch session ${sessionId} for uid ${uid}:`, err);
      }
    }

>>>>>>> 77a30ac7fe12bd6a2c9456c665eb467690f6fab6
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

      const checks = sessionResult.getChecks();
      
      // Check if all checks have completed
      let allChecksComplete = true;
      let approved = true;

      for (const check of checks) {
        const recommendation = check.getReport()?.getRecommendation()?.getValue();
        
        if (!recommendation || recommendation === 'PENDING') {
          // Check still processing
          allChecksComplete = false;
          break;
        }
        
        if (recommendation !== 'APPROVE') {
          approved = false;
        }
      }

      // Determine final status
      let finalStatus: string;
      if (!allChecksComplete) {
        finalStatus = 'processing'; // Still being reviewed
      } else if (approved) {
        finalStatus = 'processing'; // Passed Yoti, now in our onboarding
      } else {
        finalStatus = 'denied'; // Failed checks
      }

      const update: Record<string, any> = {
        verificationStatus: finalStatus,
      };
      
      console.log(`📩 Webhook: Session ${session_id} → ${finalStatus} (approved=${approved}, complete=${allChecksComplete})`);

      // COMMENTED OUT: Our custom deduplication logic - Yoti will provide their own solution
      // Uncomment below when ready to use our hash-based deduplication:
      // if (approved && allChecksComplete) {
      //   const dedupResult = await checkIdentityDuplication(sessionResult, userId);
      //   if (dedupResult.isDuplicate) {
      //     update.verificationStatus = 'locked';
      //     update.identityDuplicate = true;
      //     console.log(`📩 Webhook: 🔒 DUPLICATE DETECTED - Account locked: ${userId}`);
      //   } else if (dedupResult.identityHash) {
      //     update.identityHash = dedupResult.identityHash;
      //     console.log(`📩 Webhook: Unique identity verified for user ${userId}`);
      //   }
      // }

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

        await db.collection('user_metadata').doc(userId).update(update);
        console.log(`✅ Updated verification status for user ${userId}:`, update);
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
