import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "./models/User.js";
import { sendOTP,generateOTP, resetOTP , sendReset, sendEmail } from "./mail.js";
import { requireAuth, requireAdmin, validateBody, otpLimiter, loginLimiter } from "./middlewares/index.js";
const router = express.Router();

router.get('/users', async (req, res) => {
  const search = req.query.search;

  let query = {};
  if (search) {
    query = {
      $or: [
        { email: { $regex: search, $options: 'i' } },
        { username: { $regex: search, $options: 'i' } }
      ]
    };
  }

  try {
    const users = await User.find(query);
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: 'Server Error' });
  }
});
router.delete("/delete-me", requireAuth, async (req, res) => {
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
});
router.delete("/admin/delete/:id", requireAdmin, async (req, res) => {
  await User.findByIdAndDelete(req.params.id);
  res.json({ message: "User deleted by admin" });
});
router.patch("/admin/update-role/:id", requireAdmin, async (req, res) => {
  const { role } = req.body;
  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ message: "Invalid role" });
  }

  const updatedUser = await User.findByIdAndUpdate(
    req.params.id,
    { role },
    { new: true }
  );
  res.json({ message: "Role updated", user: updatedUser });
});

router.get("/me", requireAuth, async (req, res) => {
  console.log("🔥 [GET] /me hit");
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("-password -otp -otpExpires"); // ไม่ส่งข้อมูลลับ

    if (!user) return res.status(404).json({ message: "User not found" });

    res.json({ user }); // ส่งข้อมูลจริง เช่น email, username
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});
// Register + OTP
router.post("/register", async (req, res) => {
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
});

// Verify OTP after register
router.post("/verify-otp", async (req, res) => {
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
});
router.post ("/resend-otp", otpLimiter, async (req, res) => {
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
})
// Login normal
router.post("/login", loginLimiter, async (req, res) => {
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
});
// Logout route
router.post("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
  });
  res.json({ message: "Logged out" });
});
// Request password reset
router.post("/request-reset", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.json({ message: "If user exists, email sent" });
  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
  user.resetToken = token;
  user.resetExpires = new Date(Date.now() + 15 * 60 * 1000);
  await user.save();
  const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  await sendReset(email, link);
  res.json({ message: "Reset email sent" });
});

// Perform reset
router.post("/reset-password", async (req, res) => {
  const { token, password } = req.body;
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (!user || user.resetToken !== token || user.resetExpires < Date.now())
      throw Error();
    user.password = await bcrypt.hash(password, 10);
    user.resetToken = user.resetExpires = null;
    await user.save();
    res.json({ message: "Password updated" });
  } catch {
    res.status(400).json({ error: "Invalid/reset token expired" });
  }
});
router.post("/change-password", requireAuth, async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  if (!oldPassword || !newPassword) {
    return res.status(400).json({ message: "Missing password fields" });
  }

  try {
    const user = await User.findById(req.user._id);

    // 1. เช็กว่าเปลี่ยนภายใน 24 ชม. มั้ย
    const now = new Date();
    if (
      user.lastPasswordChange &&
      now - user.lastPasswordChange < 24 * 60 * 60 * 1000
    ) {
      return res.status(429).json({ message: "Can change password once per day" });
    }

    // 2. เช็ก old password
    const match = await bcrypt.compare(oldPassword, user.password);
    if (!match) {
      return res.status(401).json({ message: "Old password incorrect" });
    }

    // 3. เปลี่ยนรหัส
    const hashed = await bcrypt.hash(newPassword, 10);
    user.password = hashed;
    user.lastPasswordChange = now;
    await user.save();

    res.json({ message: "Password changed" });
  } catch (err) {
    console.error("Change password error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
router.post("/admin/unlock/:id", requireAuth, requireAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    const user = await User.findById(id);
    if (!user) return res.status(404).json({ message: "User not found" });

    if (!user.isLocked) {
      return res.status(400).json({ message: "User is not locked" });
    }
    await sendEmail(user.email, {
      subject: "🔓 Account Unlocked",
      text: `บัญชีของคุณถูกปลดล็อกโดยผู้ดูแลระบบเรียบร้อยแล้ว`,
    });
    user.isLocked = false;
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    res.json({ message: `User ${user.email} unlocked by admin` });
  } catch (err) {
    console.error("Unlock error:", err);
    res.status(500).json({ message: "Server error" });
  }
});
export default router;
