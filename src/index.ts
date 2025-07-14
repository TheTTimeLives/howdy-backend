import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import cors from 'cors';
import { json } from 'body-parser';
import { authRouter } from './routes/auth';
import { enqueueRouter } from './routes/enqueue';
import { tokenRouter } from './routes/token';
import { usersRouter } from './routes/users';
import { categoriesRouter } from './routes/categories';
import { yotiRouter } from './routes/yoti';
import { matchQueueRouter } from './routes/matchQueue';
import { matchActionsRouter } from './routes/matchActions';
import { agoraRouter } from './routes/agora';


const app = express();
app.use(cors());
app.use(json());

app.use('/enqueue', enqueueRouter);
app.use('/calls/token', tokenRouter);
app.use('/users', usersRouter);
app.use('/auth', authRouter);
app.use('/categories', categoriesRouter);
app.use('/yoti', yotiRouter);
app.use('/matchQueue', matchQueueRouter);
app.use('/match', matchActionsRouter);
app.use('/agora', agoraRouter);



const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
