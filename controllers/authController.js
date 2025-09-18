import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';

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
        return res.json({ success : true})

    }
    catch (error){
        return res.json({message : error.message, success : false});
    }
}

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