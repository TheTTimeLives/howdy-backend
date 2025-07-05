import express from 'express';
import { verifyJwt } from '../verifyJwt';
import { RtcTokenBuilder, RtcRole } from 'agora-access-token';

export const tokenRouter = express.Router();
tokenRouter.use(verifyJwt);

const APP_ID = process.env.AGORA_APP_ID!;
const APP_CERTIFICATE = process.env.AGORA_APP_CERTIFICATE!;
const TOKEN_EXPIRATION = 3600;

tokenRouter.post('/', (req, res) => {
  const uid = (req as any).uid;
  const { channelName } = req.body;

  if (!channelName) {
    return res.status(400).json({ error: 'Missing channelName' });
  }

  try {
    const token = RtcTokenBuilder.buildTokenWithUid(
      APP_ID,
      APP_CERTIFICATE,
      channelName,
      uid,
      RtcRole.PUBLISHER,
      Math.floor(Date.now() / 1000) + TOKEN_EXPIRATION
    );

    res.status(200).json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Failed to generate token' });
  }
});
