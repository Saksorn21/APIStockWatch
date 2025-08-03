import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "./models/User.js";
import { sendOTP,generateOTP, resetOTP , sendReset } from "./mail.js";
import { requireAuth, requireAdmin, validateBody, otpLimiter } from "./middlewares/index.js";
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
router.delete("/delete-me", async (req, res) => {
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

router.get("/me", async (req, res) => {
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
  const { email, password } = req.body;
  let user = await User.findOne({ email });
  if (user) return res.status(400).json({ error: "User exists" });
  const otp = generateOTP()
  const hashed = await bcrypt.hash(password, 10);
  const expires = new Date(Date.now() + 5 * 60 * 1000);
  user = await User.create({
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
router.post ("/resend-otp", async (req, res) => {
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
router.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(401).json({ error: "No user" });
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) return res.status(401).json({ error: "Bad credentials" });
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

export default router;
