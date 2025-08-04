import jwt from "jsonwebtoken";
import { User } from "../models/User.js";
export const requireAdmin = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) return res.status(401).json({ message: "Unauthorized" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);
    if (user.role !== 'admin') return res.status(403).json({ message: "Admin only" });

    req.user = user; // เผื่อใช้ต่อ
    next();
  } catch (err) {
    res.status(401).json({ message: "Invalid token" });
  }
};