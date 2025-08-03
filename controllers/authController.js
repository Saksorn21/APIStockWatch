import { User } from "../models/User.js"
import { generateOTP, resetOTP } from "../mail.js"
import jwt from "jsonwebtoken"
import bcrypt from "bcryptjs"
import { sendEmail, sendOTP } from "../mail.js"
export const authRegister = async (req, res) => {
    const { username, email, password } = req.body;
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ error: "User exists" });
    const otp = generateOTP()
    const hashed = await bcrypt.hash(password, 10);
    const expires = new Date(Date.now() + 5 * 60 * 1000);
    user = await User.create({
      username,
      email,
      password: hashed,
      otp,
      otpExpires: expires,
    });
    await sendOTP(email, otp);
    res.json({ message: "OTP sent to email" });
  }
export const authLogin = async (req, res) => {
    const { email, username, password } = req.body;

    try {
      // ✅ หา user จาก email หรือ username
      const user = await User.findOne({
        $or: [{ email }, { username }],
      });

      if (!user) return res.status(401).json({ error: "No user found" });

      // ✅ เช็กว่าบัญชีถูกล็อกหรือยัง
      if (user.isLocked && user.lockUntil > Date.now()) {
        return res.status(403).json({ message: "Account locked. Try again later." });
      }

      // ✅ เช็กรหัสผ่าน
      const ok = await bcrypt.compare(password, user.password);
      if (!ok) {
        user.failedLoginAttempts += 1;

        // ✅ ล็อกบัญชีถ้าผิด 5 ครั้งติด
        if (user.failedLoginAttempts >= 5) {
          user.isLocked = true;
          user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); // ล็อก 30 นาที
          await user.save();

          // ✅ แจ้งเตือนทางอีเมล
          await sendEmail(user.email, {
            subject: "🚨 Account Locked",
            text: `บัญชีคุณถูกล็อกชั่วคราว หลังพยายามล็อกอินผิด 5 ครั้งติดกัน.`,
          });

          return res.status(403).json({ message: "Account locked for 30 minutes." });
        }

        await user.save();
        return res.status(401).json({ error: "Bad credentials" });
      }

      // ✅ ล็อกอินสำเร็จ → รีเซ็ตทุกอย่าง
      user.failedLoginAttempts = 0;
      user.isLocked = false;
      user.lockUntil = null;
      await user.save();

      const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
        expiresIn: "1h",
      });

      res.cookie("token", token, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 3600000,
      });

      res.json({ message: "Logged in" });

    } catch (err) {
      console.error("🔥 Login error:", err);
      res.status(500).json({ message: "Server error" });
    }
  }
export const authLogout = (req, res) => {
    res.clearCookie("token", {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    });
    res.json({ message: "Logged out" });
  }
export const getMe = async (req, res) => {
    console.log("🔥 [GET] /me hit");
       const user = await User.findById(req.user.id).select("-password -otp -otpExpires");
      if (!user) return res.status(404).json({ message: "User not found" });

      res.json({ user }); 
  }
export const deleteMe = async (req, res) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ message: "Unauthorized" });

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      await User.findByIdAndDelete(decoded.id);
      res.clearCookie("token");
      res.json({ message: "Account deleted" });
    } catch (err) {
      res.status(500).json({ message: "Server Error" });
    }
  }