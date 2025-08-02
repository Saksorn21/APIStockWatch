import mongoose from "mongoose";
const schema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: String,
  otp: String,
  otpExpires: Date,
  resetToken: String,
  resetExpires: Date,
  googleId: String
});
export const User = mongoose.model("User", schema);