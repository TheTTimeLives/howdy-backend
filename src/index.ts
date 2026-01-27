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
import { callsRouter, assemblyAiWebhookHandler } from './routes/calls';
import { devicesRouter, devicesPublicRouter } from './routes/devices';
import { eventsRouter } from './routes/events';
import { availabilityRouter } from './routes/availability';

// eslint-disable-next-line @typescript-eslint/no-var-requires
const cron = require('node-cron');

const app = express();

/* ===== Raw-body webhook endpoints (must be before json()) ===== */
app.post('/webhooks/assemblyai', express.json({ limit: '20mb' }), assemblyAiWebhookHandler);

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

  // Lightweight TTL cleanup for stale matchQueue entries
  const cron2 = require('node-cron');
  cron2.schedule('*/1 * * * *', async () => {
    try {
      const { db } = await import('./firebase');
      const cutoffPending = Date.now() - 60_000; // 60s for match-pending
      const cutoffAccepted = Date.now() - 120_000; // 120s for match-accepted-pending

      const pendingSnap = await db.collection('matchQueue')
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
          timestamp: Date.now(),
        });
      }

      const acceptedSnap = await db.collection('matchQueue')
        .where('state', '==', 'match-accepted-pending')
        .where('timestamp', '<', cutoffAccepted)
        .get();

      for (const doc of acceptedSnap.docs) {
        await doc.ref.update({
          state: 'searching',
          partnerId: null,
          channelName: null,
          accepted: false,
          timestamp: Date.now(),
        });
      }
    } catch (e) {
      console.warn('⚠️ matchQueue TTL cleanup failed:', e);
    }
  });
  console.log('⏰ matchQueue TTL cleanup scheduled every minute');
} catch (e) {
  console.warn('⚠️ Failed to schedule transcript backfill cron:', e);
}
