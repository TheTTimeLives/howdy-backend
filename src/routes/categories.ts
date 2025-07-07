import express from 'express';
import { db } from '../firebase';
import { verifyJwt } from '../verifyJwt';

export const categoriesRouter = express.Router();

categoriesRouter.get('/', verifyJwt, async (req, res) => {
  try {
    const categorySnapshot = await db.collection('categories').get();
    const categories: any[] = [];

    for (const catDoc of categorySnapshot.docs) {
      const catId = catDoc.id;
      const catData = catDoc.data();
      const catName = catData.name ?? catId;
      const poolIds: string[] = catData.pools || [];

      const pools: { id: string; name: string }[] = [];

      for (const poolId of poolIds) {
        try {
          const poolDoc = await db.collection('pools').doc(poolId).get();
          if (poolDoc.exists) {
            const poolData = poolDoc.data();
            pools.push({
              id: poolDoc.id,
              name: poolData?.name ?? poolDoc.id,
            });
          } else {
            console.warn(`⚠️ Pool not found: ${poolId}`);
          }
        } catch (err) {
          console.error(`❌ Error fetching pool ${poolId}:`, err);
        }
      }

      categories.push({
        id: catId,
        name: catName,
        pools,
      });
    }

    res.status(200).json({ categories });
  } catch (e) {
    console.error('❌ Failed to fetch categories:', e);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});
