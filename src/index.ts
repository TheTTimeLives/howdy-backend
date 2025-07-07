import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { json } from 'body-parser';
import { authRouter } from './routes/auth';
import { enqueueRouter } from './routes/enqueue';
import { tokenRouter } from './routes/token';
import { usersRouter } from './routes/users';
import { categoriesRouter } from './routes/categories';

dotenv.config();

const app = express();
app.use(cors());
app.use(json());

app.use('/enqueue', enqueueRouter);
app.use('/calls/token', tokenRouter);
app.use('/users', usersRouter);
app.use('/auth', authRouter);
app.use('/categories', categoriesRouter);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
