import mongoose from "mongoose";
const options = {
  timestamps: true,       // เพิ่ม createdAt และ updatedAt ให้อัตโนมัติ
  versionKey: false,      // ปิดการสร้าง __v เวอร์ชัน
}
const schema = new mongoose.Schema({
  username: {
    type: String,
    unique: true,
    required: true,
    minlength: [6, 'Username must be at least 6 characters'],
    maxlength: [20, 'Username must be at most 20 characters']
  },
  email: {   
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    match: [/.+\@.+\..+/, 'Please fill a valid email address']
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
  googleId: String,
  lastPasswordChange: {
    type: Date,
    default: null,
  },
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },
  isLocked: {
    type: Boolean,
    default: false,
  },
  lockUntil: {
    type: Date,
    default: null,
  }
}, options);
export const User = mongoose.model("User", schema);