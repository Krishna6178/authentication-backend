import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

export const register = async (req,res) => {
    const {name,email,password} = req.body;

    if(!name || !email || !password){
        return res.json({message : 'All fields are required', success : false});
    }

    try {
        const existingUser = await userModel.findOne({email});
        if(existingUser){
            return res.json({message : 'User already Exists', success : false});
        }
        const hashedpassword = await bcrypt.hash(password, 10);

        const newUser = new userModel({name, email,password : hashedpassword});
        await newUser.save();

        const token = jwt.sign({id : newUser._id}, process.env.JWT_SECRET, {expiresIn : '7d'});

        res.cookie('token', token, {
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge : 7 * 24 * 60 * 60 * 1000
        })

        const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to : email,
            subject : 'Welcome to Krishnas Application',
            text : `welcome to krishna's application. Your account has been created with email id : ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({ success : true})

    }
    catch (error){
        return res.json({message : error.message, success : false});
    }
}

//Checking the login
export const login = async (req,res) => {
    const {email, password} = req.body;
    if(!email || !password) {
        return res.json({success : false, message : 'Email and Password are required'});
    }
    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({message : 'Invalid User credentials', success : false})
        }
        const isMatch = await bcrypt.compare(password, user.password);
        if(!isMatch){
            return res.json({message : "Invalid Password", success : false})
        }
        const token = jwt.sign({id : user._id}, process.env.JWT_SECRET, {expiresIn : '7d'});

        res.cookie('token', token, {
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge : 7 * 24 * 60 * 60 * 1000
        })

        return res.json({ success : true})

    }catch (error){
        return res.json({success : false, message : error.message});
    }
}

//Logout from the application
export const logout = async(req,res) => {
    try {
        res.clearCookie('token',{
            httpOnly : true,
            secure : process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        })
        return res.json({success : true, message : "Logged out"})

    }catch (error){
        return res.json({success : false, message : error.message});
    }
}

//Sending OTP to email for account verification
export const sendVerifyOTP = async (req,res) => {
    try {
        const {userId} = req.body;
        const user = await userModel.findById(userId)

        if(user.isAccountVerified){
            return res.json({success : false, message : 'Account already verified'})
        }

        const otp = String(100000 + Math.floor(Math.random() * 900000));

        user.verifyOTP = otp;
        user.verifyOTPExpireAt = Date.now() + 24 * 60 * 60 * 1000

        await user.save();

        const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to : user.email,
            subject : 'Account Verification OTP',
            text : `Your OTP is ${otp}. Verify account using this OTP`
        }

        await transporter.sendMail(mailOptions);

        res.json({ success : true, message : 'Verification OTP sent to your email address'})

    } catch(error){
        return res.json({success : false, message : error.message});
    }
}

//Verifing the user
export const verifyEmail = async (req,res) => {
    const {userId, otp} = req.body;
    if(!userId || !otp){
        return res.json({success : false, message : "Missing Details"})
    }
    try {
        const user = await userModel.findById(userId);
        if(!user){
            return res.json({success : false, message : 'User not found'})
        }

        if(user.verifyOTP === '' || user.verifyOTP !== otp){
            return res.json({success : false, message : 'Invalid OTP'})
        }
        if(user.verifyOTPExpireAt < Date.now()){
            return res.json({success : false, message : 'OTP Expired'})
        }
        user.isAccountVerified = true;
        user.verifyOTP = '';
        user.verifyOTPExpireAt = 0;

        await user.save();

        return res.json({success : true, message : 'Email Verified Successfully'})

    } catch(error){
        return res.json({success : false, message : error.message});
    }
}

//Checking weather user was authenticated or not
export const isAuthenticated = async (req,res) => {
    try{
        return res.json({success : true});
    } catch(error){
        return res.json({success : false, message : error.message});
    }
}

//Sending Reset OTP
export const sendResetOTP = async (req, res) => {
    const {email} = req.body;
    if(!email){
        return res.json({success : false, message : 'Email is required'});
    }
    try {
        const user = await userModel.findOne({email})
        if(!user){
            return res.json({success : false, message : 'User not found'});
        }
        const otp = String(100000 + Math.floor(Math.random() * 900000));
        user.resetOTP = otp;
        user.resetOTPExpireAt = Date.now() +  15 * 60 * 1000

        await user.save();

        const mailOptions = {
            from : process.env.SENDER_EMAIL,
            to : user.email,
            subject : 'Password Reset OTP',
            text : `Your OTP for resetting your password is ${otp}. Use this OTP to proceed with resetting your password`
        }

        await transporter.sendMail(mailOptions);

        res.json({ success : true, message : 'Reset OTP has sent to your email address'})

    } catch(error){
        return res.json({success : false, message : error.message});
    }

}

//Reset User Password
export const ResetPassword = async (req,res) => {
    const {email, otp, newPassword} = req.body;
    if(!email || !otp || !newPassword){
        console.log("User not found")
        return res.json({success : false, message : "Email, OTP and New Password are required"});
    }
    try {
        const user = await userModel.findOne({email});
        console.log("User not found")
        if(!user){
            return res.json({success : false, message : 'User not found'});
        }

        if(user.resetOTP === '' || user.resetOTP !== otp){
            return res.json({success : false, message : 'Invalid OTP'});
        }

        if(user.resetOTPExpireAt < Date.now()){
            return res.json({success : false, message : 'OTP Expired'});
        }

        const hashedPassword =await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        user.resetOTPExpireAt = 0;
        user.resetOTP = ''

        await user.save();
        return res.json({success : true, message : "Password has been reset successfully"});


    } catch(error){
        return res.json({success : false, message : error.message});
    }
}