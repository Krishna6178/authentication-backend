import mongoose from "mongoose";

const connectDB = async () => {
    mongoose.connection.on('connected', () => {
       console.log('MongoDB connected successfully');
   })
   mongoose.connection.on('error', (err) => {
       console.log('MongoDB connection failed', err);
   })
   const con =await mongoose.connect(`${process.env.MONGODB_URI}/mern-auth`);
   console.log(`MongoDB connected: ${con.connection.host}`);
}

export default connectDB;