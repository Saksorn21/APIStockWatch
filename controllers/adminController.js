import { User } from "../models/User.js";
export const adminDeleteUser = async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    res.json({ message: "User deleted by admin" });
  }
export const adminUpdateRole = async (req, res) => {
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
  }
export const adminUnLocked = async (req, res) => {
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
}