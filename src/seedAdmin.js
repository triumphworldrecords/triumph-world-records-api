import 'dotenv/config';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { Admin } from './models.js';

if (!process.env.MONGO_URI || !process.env.ADMIN_EMAIL || !process.env.ADMIN_PASSWORD || !process.env.JWT_SECRET) {
  throw new Error('Set MONGO_URI, ADMIN_EMAIL, ADMIN_PASSWORD and JWT_SECRET in .env');
}
await mongoose.connect(process.env.MONGO_URI);
const email = process.env.ADMIN_EMAIL.toLowerCase().trim();
const existing = await Admin.findOne({ email });
if (existing) {
  console.log('Admin already exists; no password changes made.');
} else {
  const passwordHash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
  await Admin.create({ name: process.env.ADMIN_NAME || 'Administrator', email, passwordHash, role: 'superadmin' });
  console.log('Initial admin created. Remove seed credentials from environment after use.');
}
await mongoose.disconnect();
