import express from 'express';
import { isAuthenticated, login, logout, register, ResetPassword, sendResetOTP, sendVerifyOTP, verifyEmail } from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth, sendVerifyOTP);
authRouter.post('/verify-account', userAuth, verifyEmail);
authRouter.post('/is-authenticated', userAuth, isAuthenticated);
authRouter.post('/send-reset-otp',sendResetOTP);
authRouter.post('/reset-password',ResetPassword);

export default authRouter;