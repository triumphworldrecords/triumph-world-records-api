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


// Admin logout
app.post('/api/admin/logout', (_req, res) => {
  res.clearCookie('tw_admin', {
    httpOnly: true,
    secure: isProd,
    sameSite: isProd ? 'none' : 'lax',
    path: '/',
  });

  res.json({ message: 'Signed out successfully.' });
});

// Admin profile
app.get('/api/admin/me', requireAdmin, (req, res) => {
  res.json({ admin: safeAdmin(req.admin) });
});

// Dashboard statistics
app.get('/api/admin/stats', requireAdmin, async (_req, res, next) => {
  try {
    const [
      totalApplications,
      pendingApplications,
      approvedApplications,
      rejectedApplications,
      totalAwards,
      totalTeamMembers,
      totalVideos,
      totalCertificates,
    ] = await Promise.all([
      Application.countDocuments(),
      Application.countDocuments({ status: 'Pending' }),
      Application.countDocuments({ status: 'Approved' }),
      Application.countDocuments({ status: 'Rejected' }),
      Award.countDocuments(),
      TeamMember.countDocuments(),
      Video.countDocuments(),
      Certificate.countDocuments(),
    ]);

    res.json({
      totalApplications,
      pendingApplications,
      approvedApplications,
      rejectedApplications,
      totalAwards,
      totalTeamMembers,
      totalVideos,
      totalCertificates,
    });
  } catch (error) {
    next(error);
  }
});

// Admin applications list
app.get('/api/admin/applications', requireAdmin, async (req, res, next) => {
  try {
    const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
    const limit = Math.min(
      100,
      Math.max(1, Number.parseInt(req.query.limit, 10) || 50)
    );

    const filter = {};
    const status = String(req.query.status || '').trim();
    const search = String(req.query.search || '').trim();

    if (status && status !== 'All') {
      filter.status = status;
    }

    if (search) {
      const safeSearch = search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

      filter.$or = [
        { fullName: { $regex: safeSearch, $options: 'i' } },
        { email: { $regex: safeSearch, $options: 'i' } },
        { applicationNo: { $regex: safeSearch, $options: 'i' } },
        { recordTitle: { $regex: safeSearch, $options: 'i' } },
      ];
    }

    const [items, total] = await Promise.all([
      Application.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      Application.countDocuments(filter),
    ]);

    res.json({
      items,
      total,
      page,
      pages: Math.ceil(total / limit),
    });
  } catch (error) {
    next(error);
  }
});

// Approve or reject applications
app.patch(
  '/api/admin/applications/:id/review',
  requireAdmin,
  async (req, res, next) => {
    try {
      const parsed = z
        .object({
          status: z.enum(['Approved', 'Rejected']),
          reviewNote: z.string().trim().max(2000).optional().default(''),
        })
        .safeParse(req.body);

      if (!parsed.success) {
        return res.status(400).json({
          message: 'Invalid review details.',
        });
      }

      const application = await Application.findById(req.params.id);

      if (!application) {
        return res.status(404).json({
          message: 'Application not found.',
        });
      }

      application.status = parsed.data.status;
      application.reviewNote = parsed.data.reviewNote;
      application.reviewedAt = new Date();

      if (
        parsed.data.status === 'Approved' &&
        !application.certificateNo
      ) {
        application.certificateNo =
          `TWR-${new Date().getFullYear()}-${randomUUID()
            .slice(0, 8)
            .toUpperCase()}`;
      }

      await application.save();

      res.json({
        message: 'Application review updated.',
        application,
      });
    } catch (error) {
      next(error);
    }
  }
);

// Admin content management
function registerAdminCollection({
  route,
  Model,
  requiredFields = [],
  sort = { createdAt: -1 },
}) {
  app.get(`/api/admin/${route}`, requireAdmin, async (_req, res, next) => {
    try {
      const items = await Model.find().sort(sort);
      res.json(items);
    } catch (error) {
      next(error);
    }
  });

  app.post(`/api/admin/${route}`, requireAdmin, async (req, res, next) => {
    try {
      for (const field of requiredFields) {
        if (
          req.body[field] === undefined ||
          req.body[field] === null ||
          String(req.body[field]).trim() === ''
        ) {
          return res.status(400).json({
            message: `${field} is required.`,
          });
        }
      }

      const item = await Model.create(req.body);
      res.status(201).json(item);
    } catch (error) {
      next(error);
    }
  });

  app.put(
    `/api/admin/${route}/:id`,
    requireAdmin,
    async (req, res, next) => {
      try {
        const item = await Model.findByIdAndUpdate(
          req.params.id,
          req.body,
          { new: true, runValidators: true }
        );

        if (!item) {
          return res.status(404).json({
            message: 'Item not found.',
          });
        }

        res.json(item);
      } catch (error) {
        next(error);
      }
    }
  );

  app.delete(
    `/api/admin/${route}/:id`,
    requireAdmin,
    async (req, res, next) => {
      try {
        const item = await Model.findByIdAndDelete(req.params.id);

        if (!item) {
          return res.status(404).json({
            message: 'Item not found.',
          });
        }

        res.json({ message: 'Deleted successfully.' });
      } catch (error) {
        next(error);
      }
    }
  );
}

registerAdminCollection({
  route: 'awards',
  Model: Award,
  requiredFields: ['title'],
  sort: { year: -1, createdAt: -1 },
});

registerAdminCollection({
  route: 'team',
  Model: TeamMember,
  requiredFields: ['name'],
});

registerAdminCollection({
  route: 'videos',
  Model: Video,
  requiredFields: ['title'],
});

registerAdminCollection({
  route: 'certificates',
  Model: Certificate,
  requiredFields: ['certificateNo', 'holderName'],
});

registerAdminCollection({
  route: 'announcements',
  Model: Announcement,
  requiredFields: ['title'],
});

// Admin file upload
app.post(
  '/api/admin/upload',
  requireAdmin,
  upload.single('file'),
  (req, res) => {
    if (!req.file) {
      return res.status(400).json({
        message: 'Please select a file.',
      });
    }

    const fileUrl =
      `${req.protocol}://${req.get('host')}/uploads/${req.file.filename}`;

    res.status(201).json({
      message: 'File uploaded successfully.',
      url: fileUrl,
      filename: req.file.filename,
      mimetype: req.file.mimetype,
      size: req.file.size,
    });
  }
);

// Unknown API route
app.use('/api', (_req, res) => {
  res.status(404).json({
    message: 'API route not found.',
  });
});

// Error handler
app.use((error, _req, res, _next) => {
  console.error('API error:', error);

  if (error.code === 11000) {
    return res.status(409).json({
      message: 'A record with this value already exists.',
    });
  }

  if (error.name === 'ValidationError') {
    return res.status(400).json({
      message: error.message,
    });
  }

  if (error.name === 'CastError') {
    return res.status(400).json({
      message: 'Invalid ID or value.',
    });
  }

  if (error instanceof multer.MulterError) {
    return res.status(400).json({
      message: error.message,
    });
  }

  res.status(500).json({
    message: isProd
      ? 'Something went wrong on the server.'
      : error.message || 'Unexpected server error.',
  });
});

// Connect MongoDB and start the server
async function startServer() {
  try {
    console.log('Connecting to MongoDB Atlas...');

    await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 15000,
    });

    console.log('MongoDB connected successfully.');

    app.listen(port, '0.0.0.0', () => {
      console.log(`Triumph World Records API listening on ${port}`);
    });
  } catch (error) {
    console.error('Server startup failed:', error);
    process.exit(1);
  }
}

startServer();

