import nodemailer from "nodemailer";
import dotenv from "dotenv"; dotenv.config();

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});
export const mailOptions = (to, otp) => {return {
  from: '"PortSnap" <no-reply@portsnap.com>',
  to,
  subject: "Your OTP Code",
  html: `
    <p>Your OTP is:</p>
    <p><strong>${otp}</strong></p>
    <form>
      <input type="text" name="otp" autocomplete="one-time-code" value="${otp}" readonly style="opacity:0;position:absolute;left:-9999px;">
    </form>
    <p>This code will expire in 10 minutes.</p>
  `,
}}
export const generateOTP = () => Math.floor(100000 + Math.random() * 900000).toString();
export async function sendOTP(to, otp) {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: "Your OTP Code",
    html: `<p>Your OTP is <b>${otp}</b>, valid 5 นาที</p>`
  });
}
export async function resetOTP(email,otp) {
   await transporter.sendMail(mailOptions(email,otp))
}

export async function sendReset(to, link) {
  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to,
    subject: "Reset your password",
    html: `<p>คลิกลิงก์เพื่อ reset: <a href="${link}">${link}</a></p>`
  });
}