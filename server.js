import express from 'express'
import cors from 'cors';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRoutes.js';
import dotenv from 'dotenv';
import userRouter from './routes/userRoutes.js';
dotenv.config();

const app = express();

const PORT = process.env.PORT || 4000;

connectDB();

app.use(express.json());
app.use(cors({credentials:true}));
app.use(cookieParser());

//API Endpoints
app.get('/', (req,res) => {
    console.log('App was running');
})
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

app.listen(PORT, () => {
    console.log(`Server is running on Port ${PORT}`);
})