import rateLimit from "express-rate-limit";

export const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 นาที
  max: 3,
  message: "Too many OTP requests. Try again later.",
});

export const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 นาที
  max: 5, // ล็อกอินได้แค่ 5 ครั้ง
  message: "Too many login attempts. Try again in 5 minutes.",
})