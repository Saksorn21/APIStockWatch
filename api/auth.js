import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "./models/User.js";
import { sendOTP, sendReset } from "./mail.js";

const router = express.Router();
router.get("/me", (req, res) => {
  console.log("🔥 [GET] /me hit"); // Log นี้จะช่วย debug
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const user = jwt.verify(token, process.env.JWT_SECRET);
    console.log("User verified:", user);
    res.json({ user }); // ✅ ต้องมี response กลับ
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
});
// Register + OTP
router.post("/register", async (req, res) => {
  const { email, password } = req.body;
  let user = await User.findOne({ email });
  if (user) return res.status(400).json({ error: "User exists" });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
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
  if (!user || user.otp !== otp || user.otpExpires < Date.now())
    return res.status(400).json({ error: "Invalid or expired OTP" });
  user.otp = null;
  user.otpExpires = null;
  await user.save();
  res.json({ message: "Registration complete" });
});


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
