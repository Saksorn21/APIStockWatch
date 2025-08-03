import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User } from "./models/User.js";
import ResetLink from "./models/ResetLink.js"
import { sendOTP,generateOTP, resetOTP , sendReset, sendEmail } from "./mail.js";
import { requireAuth, requireAdmin, validateBody, otpLimiter, loginLimiter } from "./middlewares/index.js";
import { adminUnLocked, adminUpdateRole, adminDeleteUser } from "./controllers/adminController.js"
import { changePassword, getResetToken, requestResetPassword, resetPassword, } from "./controllers/passwordController.js"
import { verifyOtp, resendOtp } from "./controllers/otpController.js"
import { deleteMe, getMe, authLogin, authLogout, authRegister } from "./controllers/authController.js"

const router = express.Router();

router.get('/users',  async (req, res) => {
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
router.delete("/delete-me", requireAuth, deleteMe);


router.get("/me", requireAuth, getMeo);
// Register + OTP
router.post("/register", requireAuth, authRegister);
// Login normal
router.post("/login", loginLimiter, authLogin);
// Logout route
router.post("/logout",requireAuth, authLogout);
// Verify OTP after register
router.post("/verify-otp", verifyOtp)
router.post ("/resend-otp", otpLimiter, resendOtp)
// get url reset password
router.get("/get-reset-token", getResetToken);
// Request password reset
router.post("/request-reset", requestResetPassword);
// Perform reset
router.post("/reset-password", resetPassword);
router.post("/change-password", requireAuth, changePassword);

// Api for Admin only
router.delete("/admin/delete/:id", requireAuth, requireAdmin, adminDeleteUser);
router.patch("/admin/update-role/:id", requireAuth, requireAdmin, adminUpdateRole);
router.post("/admin/unlock/:id", requireAuth, requireAdmin, adminUnLocked);
export default router;
