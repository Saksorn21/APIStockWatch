import { User } from "../models/User.js"
import { generateOTP, resetOTP } from "../mail.js"
export const verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });

  if (!user.otp || user.otp !== otp || user.otpExpires < Date.now()) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  // OTP ถูกต้อง → เคลียร์ OTP
  user.otp = null;
  user.otpExpires = null;
  user.isVerified = true; // เสริม: ตั้ง flag ว่ายืนยันแล้ว
  await user.save();

  res.json({ message: "OTP verified. Registration complete." });
}

export const resendOtp = async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ error: "User not found" });

    // สร้าง OTP ใหม่
    const otp = generateOTP();
    const expires = Date.now() + 10 * 60 * 1000
    user.otp = otp;
    user.otpExpires = expires;
    await user.save();
    try {
      console.info("[POST] /resend-otp hit")
      await resetOTP(email, otp);
      res.json({ message: "OTP resent" });
    } catch (err) {
      console.error(err)
      res.status(500).json({ error: "Failed to send OTP" });
    }
  }