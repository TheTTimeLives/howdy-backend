// deprectaed
import express from 'express';
import { RtcTokenBuilder, RtcRole } from 'agora-access-token';
import { verifyJwt } from '../verifyJwt';

const appId = process.env.AGORA_APP_ID!;
const appCertificate = process.env.AGORA_APP_CERTIFICATE!;
const tokenExpirationInSeconds = 3600;

export const agoraRouter = express.Router();
agoraRouter.use(verifyJwt);

agoraRouter.post('/token', async (req, res) => {
  const { channelName } = req.body;

  if (!channelName) {
    return res.status(400).json({ error: 'Missing channelName' });
  }

  const agoraUid = Math.floor(Math.random() * 1000000000);
  const role = RtcRole.PUBLISHER;
  const currentTimestamp = Math.floor(Date.now() / 1000);
  const privilegeExpiredTs = currentTimestamp + tokenExpirationInSeconds;

  const token = RtcTokenBuilder.buildTokenWithUid(
    appId,
    appCertificate,
    channelName,
    agoraUid,
    role,
    privilegeExpiredTs
  );

  return res.json({ token, agoraUid });
});