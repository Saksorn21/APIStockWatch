import rateLimit from "express-rate-limit";

export const otpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 นาที
  max: 3,
  message: "Too many OTP requests. Try again later.",
});