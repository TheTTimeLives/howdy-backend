// src/index.ts
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import { json } from 'body-parser';
import path from 'path';
import crypto from 'crypto';
import Stripe from 'stripe';

import { authRouter } from './routes/auth';
import { enqueueRouter } from './routes/enqueue';
import { usersRouter } from './routes/users';
import { categoriesRouter } from './routes/categories';
import { yotiRouter } from './routes/yoti';
import { matchQueueRouter } from './routes/matchQueue';
import { matchActionsRouter } from './routes/matchActions';
import { scheduledCallRouter } from './routes/scheduledCallRouter';
import { groupsRouter } from './routes/groups';
import { pushRouter } from './routes/pushRouter';
import { subscriptionsRouter } from './routes/subscriptions';
import { billingRouter } from './routes/billing';
import { onboardingRouter } from './routes/onboarding';
import {
  callsRouter,
  assemblyAiWebhookHandler,
  cloudflareTranscriptionWebhookHandler,
} from './routes/calls';
import { devicesRouter, devicesPublicRouter } from './routes/devices';
import { eventsRouter } from './routes/events';
import { availabilityRouter } from './routes/availability';
import { scheduleRouter } from './routes/schedule';
import { adminRouter } from './routes/admin';
import { faqRouter } from './routes/faq';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const cron = require('node-cron');

const app = express();

/* ===== Raw-body webhook endpoints (must be before json()) ===== */
app.post('/webhooks/assemblyai', express.json({ limit: '20mb' }), assemblyAiWebhookHandler);
app.post(
  '/webhooks/cloudflare-transcription',
  express.json({ limit: '20mb' }),
  cloudflareTranscriptionWebhookHandler
);

app.post('/webhooks/stripe', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const stripe = new Stripe(process.env.STRIPE_SECRET_KEY || '', { apiVersion: '2022-11-15' });
    const sig = req.headers['stripe-signature'] as string;
    const secret = process.env.STRIPE_WEBHOOK_SECRET || '';
    let event;
    try {
      event = stripe.webhooks.constructEvent(req.body, sig, secret);
    } catch (err: any) {
      console.error('❌ Stripe webhook signature verification failed', err?.message);
      return res.status(400).send(`Webhook Error: ${err?.message || 'invalid signature'}`);
    }

    switch (event.type) {
      case 'customer.subscription.created':
      case 'customer.subscription.updated':
      case 'customer.subscription.deleted': {
        const sub: any = event.data.object;
        const groupId = sub?.metadata?.rc_app_user_id || sub?.metadata?.groupId;
        const items = Array.isArray(sub?.items?.data) ? sub.items.data : [];
        const priceId: string | undefined = items[0]?.price?.id;
        const status: string = sub?.status || 'incomplete';
        const active = ['active', 'trialing', 'past_due'].includes(status);
        const tier = mapStripePriceIdToTier(priceId);
        if (groupId) {
          const { db } = await import('./firebase');
          await db.collection('groups').doc(groupId).set({
            subscriptionActive: active,
            ...(tier ? { tier } : {}),
            currentPeriodEnd: sub?.current_period_end ? Number(sub.current_period_end) * 1000 : null,
          }, { merge: true });
        }
        break;
      }
      default:
        break;
    }
    return res.json({ received: true });
  } catch (e) {
    console.error('❌ Stripe webhook handler failed', e);
    return res.status(500).send('Internal Error');
  }
});

app.post('/webhooks/revenuecat', express.raw({ type: 'application/json' }), async (req, res) => {
  try {
    const signature = String(req.header('X-RevenueCat-Signature') || '');
    const payload = JSON.parse(req.body.toString('utf8'));
    const appUserId: string | undefined = payload?.app_user_id;
    const entitlementActive = !!payload?.entitlements && Object.values(payload.entitlements).some((e: any) => !!(e as any)?.active);
    const productId: string | undefined = payload?.product_identifier;
    const tier = productId ? mapRevenueCatProductToTier(productId) : undefined;
    if (appUserId) {
      const { db } = await import('./firebase');
      await db.collection('groups').doc(appUserId).set({
        subscriptionActive: entitlementActive,
        ...(tier ? { tier } : {}),
      }, { merge: true });
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('❌ RevenueCat webhook handler failed', e);
    return res.status(500).send('Internal Error');
  }
});

function mapStripePriceIdToTier(priceId?: string): string | null {
  if (!priceId) return null;
  if (priceId === process.env.STRIPE_PRICE_BASIC) return 'basic';
  if (priceId === process.env.STRIPE_PRICE_STANDARD) return 'standard';
  if (priceId === process.env.STRIPE_PRICE_PRO) return 'pro';
  return null;
}

function mapRevenueCatProductToTier(productId: string): string | null {
  const id = (productId || '').toLowerCase();
  if (id.includes('basic')) return 'basic';
  if (id.includes('standard')) return 'standard';
  if (id.includes('pro')) return 'pro';
  return null;
}

function verifyRevenueCatSignature(rawBody: Buffer, signature: string, secret: string): boolean {
  try {
    if (!signature || !secret) return false;
    const hmac = crypto.createHmac('sha256', secret);
    hmac.update(rawBody);
    const digest = hmac.digest('base64');
    return digest === signature;
  } catch {
    return false;
  }
}

/* ===== Global middleware BEFORE routers that expect JSON bodies ===== */
app.use(cors());
// Handle CORS preflight for all routes (important for Flutter web JSON POST)
app.options('*', cors());
app.use(json());
app.use(express.static(path.join(__dirname, '../public')));

/* ===== Short invite landing (public) ===== */
app.get('/i/:token', (req, res) => {
  const token = String(req.params.token || '');
  const role = req.query.role ? String(req.query.role) : '';
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
    <meta name="apple-itunes-app" content="app-id=, app-argument=${deep}">
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Inter, sans-serif; background:#f7f7f8; padding:24px; }
      .card { max-width:560px; margin: 40px auto; background:#fff; border:1px solid #e6e6eb; border-radius:12px; padding:20px; }
      .btn { display:inline-block; padding:12px 16px; border-radius:10px; background:#d37f1c; color:#fff; font-weight:600; text-decoration:none; }
      .muted { color:#666; font-size:14px; }
      .row { display:flex; gap:12px; flex-wrap:wrap; }
      .store { display:inline-block; padding:10px 14px; border:1px solid #e6e6eb; border-radius:10px; text-decoration:none; color:#222 }
    </style>
    <script>
      (function(){
        var deep = ${JSON.stringify(deep)};
        var ua = navigator.userAgent || '';
        var isIOS = /iPhone|iPad|iPod/.test(ua);
        var isAndroid = /Android/.test(ua);
        // Try deep link first
        var start = Date.now();
        window.location.href = deep;
        // After a short delay, show the page (and optionally navigate to store)
        setTimeout(function(){
          var elapsed = Date.now() - start;
          // Keep user on this page to choose store; do not auto-jump without confirmed URLs
        }, 1500);
      })();
    </script>
  </head>
  <body>
    <div class="card">
      <h2>Open Howdy to accept your invite</h2>
      <p>If the app doesn't open automatically, tap the button:</p>
      <p><a class="btn" href="${deep}">Open in the app</a></p>
      <p class="muted">Don't have the app yet? Install it, then return to this link.</p>
      <div class="row">
        <a class="store" href="https://apps.apple.com/" target="_blank" rel="noopener">Get for iOS</a>
        <a class="store" href="https://play.google.com/store" target="_blank" rel="noopener">Get for Android</a>
      </div>
    </div>
  </body>
</html>`);
});

// Friendly alias
app.get('/invite/:token', (req, res) => {
  const token = String(req.params.token || '');
  const qs = req.url.includes('?') ? req.url.substring(req.url.indexOf('?')) : '';
  return res.redirect(302, `/i/${encodeURIComponent(token)}${qs}`);
});

/* ===== Routers ===== */
app.use('/devices', devicesPublicRouter);
app.use('/groups', groupsRouter);
app.use('/enqueue', enqueueRouter);
app.use('/calls', callsRouter);
app.use('/users', usersRouter);
app.use('/auth', authRouter);
app.use('/categories', categoriesRouter);
app.use('/yoti', yotiRouter);
app.use('/matchQueue', matchQueueRouter);
app.use('/match', matchActionsRouter);
app.use('/scheduled', scheduledCallRouter);
app.use('/push', pushRouter);
app.use('/subscriptions', subscriptionsRouter);
app.use('/billing', billingRouter);
app.use('/onboarding', onboardingRouter);
app.use('/devices', devicesRouter);
app.use('/events', eventsRouter);
app.use('/availability', availabilityRouter);
app.use('/schedule', scheduleRouter);
app.use('/admin', adminRouter);
app.use('/faq', faqRouter);

const PORT = Number(process.env.PORT) || 5000;
const HOST = '0.0.0.0';

app.listen(PORT, HOST, () => {
  console.log(`🚀 Backend is live at http://${HOST}:${PORT}`);
  console.log('🌐 If running on real device, use your machine\'s local IP.');
});

/* ===== Cron Jobs ===== */
try {
  const enableBackfill = String(process.env.ENABLE_TRANSCRIPT_BACKFILL || 'true').toLowerCase() === 'true';
  if (enableBackfill) {
    const cron = require('node-cron');
    cron.schedule('30 2 * * *', async () => {
      const { runTranscriptBackfillJob } = await import('./jobs/transcriptBackfillJob');
      await runTranscriptBackfillJob();
    });
    console.log('⏰ Transcript backfill cron scheduled for 02:30 daily');
  }

  // Audit retention: delete system_activity_audit older than AUDIT_RETENTION_DAYS (default 30). Set to 0 to disable.
  const auditRetentionDays = Math.max(0, parseInt(String(process.env.AUDIT_RETENTION_DAYS || '30'), 10));
  if (auditRetentionDays > 0) {
    const cronAudit = require('node-cron');
    cronAudit.schedule('0 3 * * *', async () => {
      try {
        const { runAuditRetentionJob } = await import('./jobs/auditRetentionJob');
        await runAuditRetentionJob();
      } catch (e) {
        console.warn('⚠️ Audit retention job failed:', e);
      }
    });
    console.log(`⏰ Audit retention cron scheduled for 03:00 daily (retention: ${auditRetentionDays} days)`);
  } else {
    console.log('⏰ Audit retention disabled (AUDIT_RETENTION_DAYS=0 or invalid)');
  }

  // Metrics aggregation: compute KPIs from calls + audit, store in metrics_monthly (Firestore, free tier)
  const metricsEnabled = String(process.env.METRICS_AGGREGATION_ENABLED || 'true').toLowerCase() === 'true';
  if (metricsEnabled) {
    const cronMetrics = require('node-cron');
    cronMetrics.schedule('0 2 1 * *', async () => {
      try {
        const { runMetricsAggregationJob } = await import('./jobs/metricsAggregationJob');
        await runMetricsAggregationJob();
      } catch (e) {
        console.warn('⚠️ Metrics aggregation job failed:', e);
      }
    });
    console.log('⏰ Metrics aggregation cron scheduled for 1st of month at 02:00');
  }

  // Lightweight TTL cleanup for stale matchQueue entries + run matchmaker
  const cron2 = require('node-cron');
  cron2.schedule('*/1 * * * *', async () => {
    try {
      const { db } = await import('./firebase');
      const now = Date.now();
      const cutoffPending = now - 60_000; // 60s for match-pending
      const cutoffAccepted = now - 120_000; // 120s for match-accepted-pending
      const staleCutoff = now - 10 * 60 * 1000; // 10 min for stale searching/waiting-for-rematch
      const orphanedCutoff = now - 5 * 60 * 1000; // 5 min for orphaned pairs

      const queueRef = db.collection('matchQueue');

      // 1. TTL: match-pending (no accept) older than 60s → reset to searching
      const pendingSnap = await queueRef
        .where('state', '==', 'match-pending')
        .where('accepted', '==', false)
        .where('timestamp', '<', cutoffPending)
        .get();

      for (const doc of pendingSnap.docs) {
        await doc.ref.update({
          state: 'searching',
          partnerId: null,
          channelName: null,
          accepted: false,
          timestamp: now,
        });
      }

      // 2. TTL: match-accepted-pending older than 120s → reset to searching
      const acceptedSnap = await queueRef
        .where('state', '==', 'match-accepted-pending')
        .where('timestamp', '<', cutoffAccepted)
        .get();

      for (const doc of acceptedSnap.docs) {
        await doc.ref.update({
          state: 'searching',
          partnerId: null,
          channelName: null,
          accepted: false,
          timestamp: now,
        });
      }

      // 3. Stale cleanup: remove searching/waiting-for-rematch with no poll in 10 min
      // Skip scheduled users still in their window (cron won't wipe them)
      const staleSnap = await queueRef
        .where('state', 'in', ['searching', 'waiting-for-rematch'])
        .limit(500)
        .get();

      let staleCount = 0;
      for (const doc of staleSnap.docs) {
        const data = doc.data() || {};
        if (data.scheduled === true && Number(data.scheduledWindowEnd || 0) > now) {
          continue; // In scheduled window, don't remove
        }
        const lastActivity = data.lastPolledAt ?? data.timestamp ?? 0;
        if (lastActivity < staleCutoff) {
          await doc.ref.delete();
          staleCount++;
        }
      }
      if (staleCount > 0) {
        console.log(`🧹 Removed ${staleCount} stale matchQueue entries (no poll in 10 min)`);
      }

      // 4. Orphaned pair cleanup: match-pending/pending-accepted where one side hasn't polled in 5 min
      const pairSnap = await queueRef
        .where('state', 'in', ['match-pending', 'match-accepted-pending'])
        .get();

      const processedPairs = new Set<string>();
      for (const doc of pairSnap.docs) {
        const uid = doc.id;
        const data = doc.data() || {};
        const partnerId = String(data.partnerId || '').trim();
        if (!partnerId) continue;

        const pairKey = [uid, partnerId].sort().join('|');
        if (processedPairs.has(pairKey)) continue;
        processedPairs.add(pairKey);

        const lastActivity = data.lastPolledAt ?? data.timestamp ?? 0;
        const partnerDoc = await queueRef.doc(partnerId).get();
        const partnerData = partnerDoc.exists ? (partnerDoc.data() || {}) : {};
        const partnerLastActivity = partnerData.lastPolledAt ?? partnerData.timestamp ?? 0;

        if (lastActivity < orphanedCutoff || partnerLastActivity < orphanedCutoff) {
          const updates: Promise<unknown>[] = [
            doc.ref.update({
              state: 'searching',
              partnerId: null,
              channelName: null,
              accepted: false,
              pendingExpiresAt: null,
              timestamp: now,
            }),
          ];
          if (partnerDoc.exists) {
            updates.push(partnerDoc.ref.update({
              state: 'searching',
              partnerId: null,
              channelName: null,
              accepted: false,
              pendingExpiresAt: null,
              timestamp: now,
            }));
          }
          await Promise.all(updates);
          console.log(`🧹 Reset orphaned pair: ${uid} and ${partnerId} (no poll in 5 min)`);
        }
      }

      // Run matchmaker to check for rematch timeouts and make new matches
      const { matchUsers } = await import('./services/matchmaker');
      await matchUsers();
    } catch (e) {
      console.warn('⚠️ matchQueue TTL cleanup failed:', e);
    }
  });
  console.log('⏰ matchQueue TTL cleanup + matchmaker scheduled every minute');

  // Fast matchmaker cadence for timeout/rematch flow
  setInterval(async () => {
    try {
      const { matchUsers } = await import('./services/matchmaker');
      await matchUsers();
    } catch (e) {
      // Silent failure - matchmaker will retry on next interval
    }
  }, 5000); // 5 seconds
  console.log('⏰ Fast matchmaker scheduled every 5 seconds');
} catch (e) {
  console.warn('⚠️ Failed to schedule transcript backfill cron:', e);
}
