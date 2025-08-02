import express from "express";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import cors from "cors";
import dotenv from "dotenv";
import authRouter from "./auth.js";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { User } from "./models/User.js";

dotenv.config();
const PORT = process.env.PORT || 8889
const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({origin:process.env.FRONTEND_URL,credentials:true}));
mongoose.connect(process.env.MONGO_URI);

// setup passport Google OAuth
passport.use(new GoogleStrategy({
  clientID:process.env.GOOGLE_CLIENT_ID,
  clientSecret:process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:`${process.env.BACKEND_URL}/api/auth/google/callback`
}, async (accessToken, refreshToken, profile, done)=>{
  let user = await User.findOne({ googleId: profile.id });
  if(!user) user = await User.create({ email: profile.emails[0].value, googleId:profile.id });
  return done(null,user);
}));
app.use(passport.initialize());

// routes
app.use("/auth", authRouter);
app.get("/auth/google", passport.authenticate("google",{scope:["email","profile"]}));
app.get("/auth/google/callback", passport.authenticate("google",{session:false,failureRedirect:`${process.env.FRONTEND_URL}/login`}), (req,res)=>{
  const token = jwt.sign({id:req.user._id}, process.env.JWT_SECRET, {expiresIn:"1h"});
  res.cookie("token",token,{httpOnly:true,secure:true,sameSite:"lax",maxAge:3600000});
  res.redirect(process.env.FRONTEND_URL);
});

app.listen(PORT, ()=> console.log("API ready at Port" + PORT));