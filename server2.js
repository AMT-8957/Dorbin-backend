require('dotenv').config();
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 4000;

if (!process.env.DATABASE_URL) {
  console.error('ERROR: DATABASE_URL is not set in .env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes('localhost')
    ? false
    : { rejectUnauthorized: false },
});

const allowedOrigins = (process.env.CORS_ORIGIN || 'https://amt-8957.github.io')
  .split(',')
  .map((o) => o.trim())
  .filter(Boolean);

app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.includes('*') || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  })
);
app.options('*', cors());
app.use(express.json());

function sha256(text) {
  return crypto.createHash('sha256').update(text).digest('hex');
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function generateOtpCode() {
  return String(crypto.randomInt(10000, 100000));
}

async function sendSmsOtp(phone, code) {
  if (process.env.KAVENEGAR_API_KEY && process.env.KAVENEGAR_TEMPLATE) {
    const url = new URL(
      `https://api.kavenegar.com/v1/${process.env.KAVENEGAR_API_KEY}/verify/lookup.json`
    );
    url.searchParams.set('receptor', phone);
    url.searchParams.set('token', code);
    url.searchParams.set('template', process.env.KAVENEGAR_TEMPLATE);

    const res = await fetch(url.toString());
    const data = await res.json();
    if (!res.ok || data?.return?.status !== 200) {
      throw new Error(data?.return?.message || 'خطا در ارسال پیامک از کاوه‌نگار');
    }
    return { sent: true, provider: 'kavenegar' };
  }

  if (process.env.OTP_DEV_MODE === 'true') {
    console.log(`[DEV OTP] Phone: ${phone} | Code: ${code}`);
    return { sent: false, provider: 'dev' };
  }

  throw new Error('سرویس پیامک در متغیرهای محیطی تنظیم نشده است');
}

// Middleware: احراز هویت با توکن Bearer و جدول sessions
async function authRequired(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    if (!token) {
      return res.status(401).json({ error: 'توکن احراز هویت ارسال نشده است' });
    }

    const tokenHash = sha256(token);
    const { rows } = await pool.query(
      `SELECT u.id, u.phone, u.role, u.first_name, u.last_name, u.national_id,
              u.institute_id, u.counselor_id, u.subscription, u.sub_until, u.is_active
       FROM sessions s
       JOIN users u ON u.id = s.user_id
       WHERE s.token_hash = $1 AND s.expires_at > now()`,
      [tokenHash]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'نشست نامعتبر یا منقضی شده است' });
    }
    if (!rows[0].is_active) {
      return res.status(403).json({ error: 'حساب کاربری غیرفعال است' });
    }

    req.user = rows[0];
    req.tokenHash = tokenHash;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    res.status(500).json({ error: 'خطای داخلی سرور در احراز هویت' });
  }
}

// 1. تست سلامت سرور و اتصال دیتابیس
app.get('/api/health', async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT now() AS server_time');
    res.json({ ok: true, db_time: rows[0].server_time });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// 2. ارسال کد OTP
async function handleSendOtp(req, res) {
  try {
    const rawPhone = (req.body?.phone || '').trim();
    if (!rawPhone) {
      return res.status(400).json({ error: 'شماره موبایل الزامی است' });
    }

    const code = generateOtpCode();
    const codeHash = sha256(code);

    await pool.query(
      `INSERT INTO otp_codes (phone, code_hash, expires_at)
       VALUES ($1, $2, now() + interval '3 minutes')`,
      [rawPhone, codeHash]
    );

    const smsResult = await sendSmsOtp(rawPhone, code);

    const payload = { ok: true, message: 'کد تایید ارسال شد' };
    if (process.env.OTP_DEV_MODE === 'true' && !smsResult.sent) {
      payload.dev_code = code;
    }
    res.json(payload);
  } catch (err) {
    console.error('Send OTP error:', err);
    res.status(500).json({ error: err.message || 'خطا در ارسال کد تایید' });
  }
}

// 3. تایید کد OTP و ورود کاربر
async function handleVerifyOtp(req, res) {
  try {
    const phone = (req.body?.phone || '').trim();
    const code = (req.body?.code || '').trim();
    if (!phone || !code) {
      return res.status(400).json({ error: 'شماره موبایل و کد تایید الزامی است' });
    }

    const { rows: otpRows } = await pool.query(
      `SELECT id, code_hash
       FROM otp_codes
       WHERE phone = $1 AND consumed = FALSE AND expires_at > now()
       ORDER BY created_at DESC
       LIMIT 1`,
      [phone]
    );

    if (otpRows.length === 0 || otpRows[0].code_hash !== sha256(code)) {
      return res.status(401).json({ error: 'کد تایید نامعتبر یا منقضی شده است' });
    }

    await pool.query('UPDATE otp_codes SET consumed = TRUE WHERE id = \$1', [otpRows[0].id]);

    let { rows: userRows } = await pool.query(
      `SELECT id, phone, role, first_name, last_name, subscription, is_active
       FROM users WHERE phone = $1`,
      [phone]
    );

    if (userRows.length === 0) {
      const inserted = await pool.query(
        `INSERT INTO users (phone, role, first_name, last_name)
         VALUES ($1, 'student', '', '')
         RETURNING id, phone, role, first_name, last_name, subscription, is_active`,
        [phone]
      );
      userRows = inserted.rows;
    }

    const user = userRows[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'حساب کاربری غیرفعال است' });
    }

    const token = generateToken();
    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '30 days')`,
      [user.id, sha256(token)]
    );

    res.json({ token, user });
  } catch (err) {
    console.error('Verify OTP error:', err);
    res.status(500).json({ error: 'خطا در تایید کد' });
  }
}

app.post('/auth/otp/send', handleSendOtp);
app.post('/api/auth/otp/send', handleSendOtp);
app.post('/auth/otp/verify', handleVerifyOtp);
app.post('/api/auth/otp/verify', handleVerifyOtp);

// 4. ثبت‌نام کاربر جدید
async function handleRegister(req, res) {
  try {
    const {
      phone,
      password,
      name = '',
      first_name = '',
      last_name = '',
      role = 'student',
      national_id = null,
    } = req.body;

    if (!phone || !password) {
      return res.status(400).json({ error: 'شماره موبایل و رمز عبور الزامی است' });
    }

    let resolvedFirstName = first_name.trim();
    let resolvedLastName = last_name.trim();
    if (!resolvedFirstName && !resolvedLastName && name && name.trim()) {
      const parts = name.trim().split(/\s+/);
      resolvedFirstName = parts[0] || '';
      resolvedLastName = parts.slice(1).join(' ');
    }

    const allowedRoles = ['student', 'counselor', 'institute'];
    const safeRole = allowedRoles.includes(role) ? role : 'student';
    const passwordHash = await bcrypt.hash(password, 10);

    const { rows } = await pool.query(
      `INSERT INTO users (phone, password_hash, role, first_name, last_name, national_id)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, phone, role, first_name, last_name, subscription`,
      [phone.trim(), passwordHash, safeRole, resolvedFirstName, resolvedLastName, national_id]
    );