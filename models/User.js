import mongoose from "mongoose";
const options = {
  timestamps: true,       // เพิ่ม createdAt และ updatedAt ให้อัตโนมัติ
  versionKey: false,      // ปิดการสร้าง __v เวอร์ชัน
}
const schema = new mongoose.Schema({
  email: {   
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: /.+\@.+\..+/
   },
  password: {
    type: String,
    required: true,
    select: false,
    minlength: 6,
    },
  role: {
    type: String,
    enum: ['user', 'admin'],  // รับแค่ 2 ค่านี้
    default: 'user'           // ถ้าไม่ใส่จะเป็น 'user'
  },
  otp: String,
  otpExpires: Date,
  isVerified: { 
    type: Boolean, 
    default: false
  },
  resetToken: String,
  resetExpires: Date,
  googleId: String
}, options);
export const User = mongoose.model("User", schema);