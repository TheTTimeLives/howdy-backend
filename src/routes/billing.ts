import express from 'express';
import Stripe from 'stripe';
import { verifyJwt } from '../verifyJwt';

const stripeSecretKey = process.env.STRIPE_SECRET_KEY || '';
const stripe = new Stripe(stripeSecretKey, {
  apiVersion: '2023-10-16',
});

export const billingRouter = express.Router();
billingRouter.use(verifyJwt);

function mapTierToPriceId(tier: string): string | null {
  switch ((tier || '').toLowerCase()) {
    case 'basic':
      return process.env.STRIPE_PRICE_BASIC || null;
    case 'standard':
      return process.env.STRIPE_PRICE_STANDARD || null;
    case 'pro':
      return process.env.STRIPE_PRICE_PRO || null;
    default:
      return null;
  }
}

// POST /billing/stripe/checkout { groupId, tier }
billingRouter.post('/stripe/checkout', async (req, res) => {
  try {
    const groupId = String(req.body?.groupId || '');
    const tier = String(req.body?.tier || '').toLowerCase();
    if (!groupId) return res.status(400).json({ error: 'Missing groupId' });
    const priceId = mapTierToPriceId(tier);
    if (!priceId) return res.status(400).json({ error: 'Invalid or unmapped tier' });

    const frontendBase = process.env.FRONTEND_BASE_URL || 'http://localhost:3000';

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      allow_promotion_codes: true,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${frontendBase}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${frontendBase}/billing/cancelled`,
      subscription_data: {
        metadata: {
          rc_app_user_id: groupId,
        },
      },
      metadata: {
        groupId,
        tier,
      },
    });

    return res.status(200).json({ url: session.url });
  } catch (e) {
    console.error('❌ create checkout session failed', e);
    return res.status(500).json({ error: 'Failed to create checkout session' });
  }
});


