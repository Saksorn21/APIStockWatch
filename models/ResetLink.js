import mongoose from 'mongoose';

const ResetLinkSchema = new mongoose.Schema({
  uuid: {
    type: String,
    required: true,
    unique: true,
  },
  token: {
    type: String,
    required: true,
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expires: 0 }, // ⏳ TTL → ลบทิ้งอัตโนมัติเมื่อหมดอายุ
  },
});

export default mongoose.model('ResetLink', ResetLinkSchema);