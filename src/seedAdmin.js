
import 'dotenv/config';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import { Admin } from './models.js';

const { MONGO_URI, ADMIN_EMAIL, ADMIN_PASSWORD, JWT_SECRET } = process.env;

if (!MONGO_URI || !ADMIN_EMAIL || !ADMIN_PASSWORD || !JWT_SECRET) {
  throw new Error(
    'Set MONGO_URI, ADMIN_EMAIL, ADMIN_PASSWORD and JWT_SECRET in environment variables.'
  );
}

if (JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters.');
}

try {
  await mongoose.connect(MONGO_URI);

  const email = ADMIN_EMAIL.toLowerCase().trim();
  const passwordHash = await bcrypt.hash(ADMIN_PASSWORD, 12);

  const admin = await Admin.findOneAndUpdate(
    { email },
    {
      $set: {
        email,
        passwordHash,
        name: process.env.ADMIN_NAME || 'Administrator',
        role: 'superadmin',
        active: true
      }
    },
    {
      new: true,
      upsert: true,
      runValidators: true,
      setDefaultsOnInsert: true
    }
  );

  console.log('Admin account updated successfully:', admin.email);
} catch (error) {
  console.error('Admin setup failed:', error.message);
  process.exitCode = 1;
} finally {
  await mongoose.disconnect();
}
