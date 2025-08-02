import nodemailer from "nodemailer";
import dotenv from "dotenv"; dotenv.config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

export async function sendOTP(to, otp) {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: "Your OTP Code",
    html: `<p>Your OTP is <b>${otp}</b>, valid 5 นาที</p>`
  });
}

export async function sendReset(to, link) {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: "Reset your password",
    html: `<p>คลิกลิงก์เพื่อ reset: <a href="${link}">${link}</a></p>`
  });
}