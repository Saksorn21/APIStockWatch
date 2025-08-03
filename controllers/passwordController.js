import { User } from "../models/User.js"
import ResetLink from "../models/ResetLink.js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"
import { sendEmail } from "../mail.js"
export const getResetToken = async (req, res) => {
    const { uuid } = req.query;
    const entry = await ResetLink.findOne({ uuid });

    if (!entry) return res.status(400).json({ error: "Invalid or expired reset link" }
    res.json({ token: entry.token });
  }
                                            
export const requestResetPassword = async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });
    if (!user) {
      console.log("Password reset requested for unknown email:", email);
      return res.json({ message: "If user exists, email sent" });
    }
    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    user.resetRequests = user.resetRequests.filter(d => d > oneDayAgo);

    if (user.resetRequests.length >= 5) {
      return res.status(429).json({ message: "Too many reset requests today" });
    }

    user.resetRequests.push(new Date());
    const token = jwt.sign({ id: user._id }, process.env.JWT_RESET_SECRET, {
      expiresIn: "15m",
    });
    const uuid = crypto.randomUUID();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    // Save to DB
    await ResetLink.create({ uuid, token, expiresAt: expires });

    const frontendURL = process.env.FRONTEND_URL.replace(/\/$/, "");
    const link = `${frontendURL}/reset/${uuid}`;
    const html = `
      <h2>🔑 Reset Your Password</h2>
      <p>Click below to reset:</p>
      <a href="${link}">Reset Password</a>
      <p>This link expires in 15 minutes.</p>
    `;
    await sendEmail(user.email, {
      subject: "Reset Your Password",
      html,
    });
  }
export const resetPassword = async (req, res) => {
    const { token, password } = req.body;
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      const user = await User.findById(decoded.id);
      if (!user) {
        return res.status(400).json({ error: "User not found" });
      }

      if (user.resetToken !== token) {
        return res.status(400).json({ error: "Invalid token" });
      }

      if (user.resetExpires < Date.now()) {
        return res.status(400).json({ error: "Token expired" });
      }
      if (await bcrypt.compare(newPassword, user.password)) {
        return res.status(400).json({ message: "New password must be different from old password" });
      }
      user.lastPasswordChange = new Date()
      user.password = await bcrypt.hash(password, 10);
      user.resetToken = user.resetExpires = null;
      await user.save();

      // ลบ ResetLink
      await ResetLink.deleteOne({ token });
      await sendEmail(user.email, {
        subject: "🔐 Password Changed",
        text: `รหัสผ่านของคุณถูกเปลี่ยนเมื่อ ${new Date().toLocaleString()}\nถ้าไม่ใช่คุณ → รีเซ็ตด่วน!`,
      });
      res.json({ message: "Password updated" });
    } catch {
      if (!user) return res.status(400).json({ error: "User not found" });
      if (user.resetToken !== token) return res.status(400).json({ error: "Invalid token" });
      if (user.resetExpires < Date.now()) return res.status(400).json({ error: "Token expired" });
    }
  }
export const changePassword = async (req, res) => {
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
}