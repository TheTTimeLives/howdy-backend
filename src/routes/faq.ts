import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const faqRouter = express.Router();

/**
 * GET /faq - Fetch FAQ items from Firestore `faq` collection.
 * Sorted by `order` (asc), then by document id.
 * Documents: { question: string, answer: string, order?: number }
 */
faqRouter.get('/', verifyJwt, async (req, res) => {
  try {
    const snapshot = await db.collection('faq').get();

    const items = snapshot.docs
      .map((doc) => {
        const data = doc.data();
        return {
          id: doc.id,
          question: data.question ?? '',
          answer: data.answer ?? '',
          order: data.order ?? 0,
        };
      })
      .sort((a, b) => a.order - b.order);

    res.status(200).json({ items });
  } catch (e) {
    console.error('❌ Failed to fetch FAQ:', e);
    res.status(500).json({ error: 'Failed to fetch FAQ' });
  }
});
