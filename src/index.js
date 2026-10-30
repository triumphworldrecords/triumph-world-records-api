import 'dotenv/config';

import dns from 'node:dns';
dns.setServers(['8.8.8.8', '1.1.1.1']);

import express from 'express';
import mongoose from 'mongoose';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';

import {
  Application,
  Admin,
  Announcement,
  Award,
  TeamMember,
  Video,
  Certificate,
} from './models.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const uploadDir = path.resolve(
  process.env.UPLOAD_DIR || path.join(__dirname, '../uploads')
);
fs.mkdirSync(uploadDir, { recursive: true });

const app = express();
app.set('trust proxy', 1);

const isProd = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT) || 5000;

if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters.');
}

if (!process.env.MONGO_URI) {
  throw new Error('MONGO_URI is missing.');
}

const allowedOrigins = (
  process.env.CLIENT_ORIGIN ||
  'https://triumphworldrecords.com,http://localhost:5173'
)
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.use(
  helmet({
    crossOriginResourcePolicy: { policy: 'cross-origin' },
  })
);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
  })
);

app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(uploadDir));

app.use(
  '/api',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 300,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
  })
);

app.use(
  '/api/admin/login',
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 8,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
  })
);

const upload = multer({
  storage: multer.diskStorage({
    destination: (_req, _file, cb) => cb(null, uploadDir),
    filename: (_req, file, cb) => {
      cb(
        null,
        `${Date.now()}-${randomUUID()}${path.extname(file.originalname).toLowerCase()}`
      );
    },
  }),
  limits: { fileSize: 260 * 1024 * 1024 },
  fileFilter: (_req, file, cb) => {
    const allowed =
      file.mimetype.startsWith('image/') ||
      file.mimetype.startsWith('video/') ||
      file.mimetype === 'application/pdf';

    if (!allowed) {
      return cb(new Error('Only image, video, and PDF files are allowed.'));
    }

    cb(null, true);
  },
});

const applicationInput = z.object({
  fullName: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254),
  phone: z.string().trim().max(30).optional().default(''),
  country: z.string().trim().min(2).max(80),
  category: z.string().trim().min(2).max(100),
  recordTitle: z.string().trim().min(3).max(180),
  description: z.string().trim().min(20).max(5000),
  evidenceUrl: z
    .string()
    .trim()
    .url()
    .max(1000)
    .optional()
    .or(z.literal(''))
    .default(''),
});

const signAdmin = (admin) =>
  jwt.sign(
    { sub: admin.id, role: admin.role },
    process.env.JWT_SECRET,
    { expiresIn: '8h', issuer: 'triumph-world-records' }
  );

async function requireAdmin(req, res, next) {
  try {
    const token = req.cookies.tw_admin;

    if (!token) {
      return res.status(401).json({ message: 'Authentication required.' });
    }

    const payload = jwt.verify(token, process.env.JWT_SECRET, {
      issuer: 'triumph-world-records',
    });

    const admin = await Admin.findOne({
      _id: payload.sub,
      active: true,
    }).select('_id name email role');

    if (!admin) {
      return res.status(401).json({ message: 'Admin account is inactive.' });
    }

    req.admin = admin;
    next();
  } catch {
    return res
      .status(401)
      .json({ message: 'Session expired. Please sign in again.' });
  }
}

const safeAdmin = (admin) => ({
  id: admin.id,
  name: admin.name,
  email: admin.email,
  role: admin.role,
});

app.get('/', (_req, res) => {
  res.status(200).json({
    success: true,
    message: 'Triumph World Records API is running.',
    health: '/api/health',
  });
});

app.get('/api/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'triumph-world-records',
  });
});

// Public application submission
app.post('/api/applications', async (req, res, next) => {
  try {
    const parsed = applicationInput.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({
        message: 'Please check the form fields.',
        errors: parsed.error.flatten().fieldErrors,
      });
    }

    const application = await Application.create({
      ...parsed.data,
      applicationNo: `TWR-${new Date().getFullYear()}-${randomUUID()
        .slice(0, 8)
        .toUpperCase()}`,
    });

    res.status(201).json({
      message: 'Application received.',
      applicationNo: application.applicationNo,
    });
  } catch (error) {
    next(error);
  }
});

// Public records
app.get('/api/records', async (_req, res, next) => {
  try {
    const records = await Application.find({ status: 'Approved' })
      .select(
        'applicationNo fullName country category recordTitle certificateNo reviewedAt description'
      )
      .sort({ reviewedAt: -1 })
      .limit(200);

    res.json(records);
  } catch (error) {
    next(error);
  }
});

// Certificate verification
app.get('/api/verify/:certificateNo', async (req, res, next) => {
  try {
    const certificateNo = req.params.certificateNo.trim();
    const certificate = await Certificate.findOne({ certificateNo });

    if (certificate) {
      return res.json({
        valid: certificate.status === 'Valid',
        certificate,
      });
    }

    const record = await Application.findOne({
      certificateNo,
      status: 'Approved',
    }).select(
      'certificateNo fullName country category recordTitle reviewedAt'
    );

    if (!record) {
      return res.status(404).json({
        valid: false,
        message: 'No certificate found.',
      });
    }

    res.json({ valid: true, record });
  } catch (error) {
    next(error);
  }
});

// Public content
app.get('/api/announcements', async (_req, res, next) => {
  try {
    res.json(
      await Announcement.find({ published: true })
        .sort({ createdAt: -1 })
        .limit(30)
    );
  } catch (error) {
    next(error);
  }
});

app.get('/api/awards', async (_req, res, next) => {
  try {
    res.json(
      await Award.find({ published: true }).sort({
        year: -1,
        createdAt: -1,
      })
    );
  } catch (error) {
    next(error);
  }
});

app.get('/api/team', async (_req, res, next) => {
  try {
    res.json(
      await TeamMember.find({ published: true }).sort({
        section: 1,
        order: 1,
        name: 1,
      })
    );
  } catch (error) {
    next(error);
  }
});

app.get('/api/videos', async (_req, res, next) => {
  try {
    res.json(
      await Video.find({ published: true })
        .populate('recordId', 'recordTitle')
        .sort({ featured: -1, createdAt: -1 })
        .limit(200)
    );
  } catch (error) {
    next(error);
  }
});

app.get('/api/certificates', async (_req, res, next) => {
  try {
    res.json(
      await Certificate.find({ status: 'Valid' })
        .select(
          'certificateNo holderName recordTitle achievementDate category type status imageUrl pdfUrl'
        )
        .sort({ createdAt: -1 })
        .limit(100)
    );
  } catch (error) {
    next(error);
  }
});

// Admin login
app.post('/api/admin/login', async (req, res, next) => {
  try {
    const parsed = z
      .object({
        email: z.string().email(),
        password: z.string().min(1).max(200),
      })
      .safeParse(req.body);

    if (!parsed.success) {
      return res
        .status(400)
        .json({ message: 'Enter a valid email and password.' });
    }

    const admin = await Admin.findOne({
      email: parsed.data.email.toLowerCase().trim(),
    });

    if (
      !admin ||
      !admin.active ||
      !(await bcrypt.compare(parsed.data.password, admin.passwordHash))
    ) {
      return res.status(401).json({ message: 'Invalid sign-in details.' });
    }

    res.cookie('tw_admin', signAdmin(admin), {
      httpOnly: true,
      secure: isProd,
      sameSite: isProd ? 'none' : 'lax',
      maxAge: 8 * 60 * 60 * 1000,
      path: '/',
    });

    res.json({ admin: safeAdmin(admin) });
  } catch (error) {
    next(error);
  }
});
