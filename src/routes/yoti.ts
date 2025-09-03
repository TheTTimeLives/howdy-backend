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

    // const notificationConfig = new NotificationConfigBuilder()
    //   .withEndpoint('https://your-domain.com/yoti-webhook')
    //   .withAuthTypeBasic()
    //   .withAuthToken(YOTI_WEBHOOK_AUTH)
    //   .forSessionCompletion()
    //   .build();

    const sessionSpec = new SessionSpecificationBuilder()
      .withClientSessionTokenTtl(600)
      .withUserTrackingId(uid)
      .withRequestedCheck(new RequestedDocumentAuthenticityCheckBuilder().build())
      .withRequestedCheck(new RequestedLivenessCheckBuilder().forStaticLiveness().withMaxRetries(3).build())
      .withRequestedCheck(new RequestedFaceMatchCheckBuilder().withManualCheckFallback().build())
      .withRequestedTask(new RequestedTextExtractionTaskBuilder().withManualCheckFallback().build())
      .withSdkConfig(sdkConfig)
    //   .withNotifications(notificationConfig)
      .build();

    const sessionResult = await idvClient.createSession(sessionSpec);
    const sessionId = sessionResult.getSessionId();
    const clientSessionToken = sessionResult.getClientSessionToken();

    // Save to Firestore
    await db.collection('user_metadata').doc(uid).set({
      yotiSessionId: sessionId,
      yotiToken: clientSessionToken,
      verificationStatus: 'processing',
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
            // .withDocumentAuthenticityCheck(docCheck)
            // .withDocumentFaceMatchCheck(faceCheck)
            // .withLivenessCheck(livenessCheck)
            // .withDocumentTextDataCheck(textCheck)
            .build()
        )
        .withTaskResults(
          new SandboxTaskResultsBuilder()
            // .withDocumentTextDataExtractionTask(textExtraction)
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
    const status = doc.data()?.verificationStatus ?? 'awaiting';
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

      const checks = sessionResult.getChecks();
      let approved = true;

      for (const check of checks) {
        const recommendation = check.getReport()?.getRecommendation()?.getValue();
        if (recommendation !== 'APPROVE') {
          approved = false;
          break;
        }
      }

      const update: Record<string, any> = {
        verificationStatus: approved ? 'approved' : 'denied',
      };

      // Optional deduplication logic (only if approved)
      if (approved) {
        const textChecks = sessionResult.getIdDocumentTextDataChecks();
        if (textChecks.length > 0) {
          const check = textChecks[0];
          const fields = (check as any).getDocumentFields?.();

          let fullName: string | undefined;
          let dob: string | undefined;
          let docNum: string | undefined;

          if (fields) {
            fullName = fields.getField('full_name')?.getValue();
            dob = fields.getField('date_of_birth')?.getValue();
            docNum = fields.getField('document_number')?.getValue();
          } else {
            console.warn('⚠️ No document fields found in sandbox check.');
          }

          if (fullName && dob && docNum) {
            const rawString = `${fullName}|${dob}|${docNum}`;
            const crypto = await import('crypto');
            const hash = crypto.createHash('sha256').update(rawString).digest('hex');

            const existing = await db
              .collection('user_metadata')
              .where('identityHash', '==', hash)
              .get();

            if (!existing.empty) {
              console.warn(`⚠️ Duplicate identity detected: ${fullName}, hash: ${hash}`);
              update.verificationStatus = 'denied';
              update.identityDuplicate = true;
            } else {
              update.identityHash = hash;
            }
          } else {
            console.warn('⚠️ One or more identity fields are missing from document');
          }
        } else {
          console.warn('⚠️ No ID document text checks found');
        }
      }

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
