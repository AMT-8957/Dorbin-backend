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
  return String(crypto.randomInt(100000, 999999));
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

    await pool.query('UPDATE otp_codes SET consumed = TRUE WHERE id = $1', [otpRows[0].id]);

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

    const user = rows[0];
    const token = generateToken();
    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '30 days')`,
      [user.id, sha256(token)]
    );

    res.status(201).json({ token, user });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'این شماره موبایل قبلاً ثبت شده است' });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'خطا در ثبت‌نام' });
  }
}

app.post('/api/auth/register', handleRegister);
app.post('/auth/signup', handleRegister);

// 5. ورود با شماره موبایل و رمز عبور
async function handleLogin(req, res) {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) {
      return res.status(400).json({ error: 'شماره موبایل و رمز عبور الزامی است' });
    }

    const { rows } = await pool.query(
      `SELECT id, phone, password_hash, role, first_name, last_name, subscription, is_active
       FROM users WHERE phone = $1`,
      [phone.trim()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ error: 'شماره موبایل یا رمز عبور اشتباه است' });
    }

    const user = rows[0];
    if (!user.is_active) {
      return res.status(403).json({ error: 'حساب کاربری غیرفعال است' });
    }

    const valid = user.password_hash ? await bcrypt.compare(password, user.password_hash) : false;
    if (!valid) {
      return res.status(401).json({ error: 'شماره موبایل یا رمز عبور اشتباه است' });
    }

    const token = generateToken();
    await pool.query(
      `INSERT INTO sessions (user_id, token_hash, expires_at)
       VALUES ($1, $2, now() + interval '30 days')`,
      [user.id, sha256(token)]
    );

    delete user.password_hash;
    res.json({ token, user });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'خطا در ورود' });
  }
}

app.post('/api/auth/login', handleLogin);
app.post('/auth/login', handleLogin);

// 6. خروج
async function handleLogout(req, res) {
  await pool.query('DELETE FROM sessions WHERE token_hash = $1', [req.tokenHash]);
  res.json({ ok: true });
}

app.post('/api/auth/logout', authRequired, handleLogout);
app.post('/auth/logout', authRequired, handleLogout);

// 7. اطلاعات پروفایل کاربر لاگین‌شده
app.get('/api/me', authRequired, (req, res) => {
  res.json({ user: req.user });
});
app.get('/auth/me', authRequired, (req, res) => {
  res.json({ user: req.user });
});

// 8. لیست دانش‌آموزان
app.get('/api/students', authRequired, async (req, res) => {
  try {
    let query = `SELECT id, phone, first_name, last_name, counselor_id, institute_id, subscription, sub_until, created_at
                 FROM users WHERE role = 'student'`;
    const params = [];

    if (req.user.role === 'counselor') {
      query += ' AND counselor_id = $1';
      params.push(req.user.id);
    } else if (req.user.role === 'institute' && req.user.institute_id) {
      query += ' AND institute_id = $1';
      params.push(req.user.institute_id);
    } else if (req.user.role === 'student') {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    query += ' ORDER BY created_at DESC';
    const { rows } = await pool.query(query, params);
    res.json({ students: rows });
  } catch (err) {
    res.status(500).json({ error: 'خطا در دریافت لیست دانش‌آموزان' });
  }
});

// 9. دریافت برنامه مطالعه و خانه‌های جدول هفتگی
app.get('/api/schedule/:studentId', authRequired, async (req, res) => {
  try {
    const studentId = req.params.studentId === 'me' ? req.user.id : req.params.studentId;
    if (req.user.role === 'student' && studentId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const schedRes = await pool.query('SELECT * FROM study_schedules WHERE student_id = $1', [studentId]);
    const cellsRes = await pool.query(
      'SELECT day, slot, subject, topic FROM weekly_cells WHERE student_id = $1 ORDER BY day, slot',
      [studentId]
    );

    res.json({
      schedule: schedRes.rows[0] || { pattern: '60-10', hours: 8, day_type: 'school', confirmed: false },
      cells: cellsRes.rows,
    });
  } catch (err) {
    res.status(500).json({ error: 'خطا در دریافت برنامه' });
  }
});

// 10. ذخیره یا بروزرسانی برنامه و خانه‌های جدول هفتگی
app.put('/api/schedule/:studentId', authRequired, async (req, res) => {
  const client = await pool.connect();
  try {
    const studentId = req.params.studentId === 'me' ? req.user.id : req.params.studentId;
    if (req.user.role === 'student' && studentId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const { pattern = '60-10', hours = 8, day_type = 'school', confirmed = false, cells = [] } = req.body;
    const counselorId = req.user.role === 'counselor' ? req.user.id : null;

    await client.query('BEGIN');

    await client.query(
      `INSERT INTO study_schedules (student_id, counselor_id, pattern, hours, day_type, confirmed, updated_at)
       VALUES ($1, $2, $3, $4, $5, $6, now())
       ON CONFLICT (student_id) DO UPDATE SET
         counselor_id = COALESCE(EXCLUDED.counselor_id, study_schedules.counselor_id),
         pattern = EXCLUDED.pattern,
         hours = EXCLUDED.hours,
         day_type = EXCLUDED.day_type,
         confirmed = EXCLUDED.confirmed,
         updated_at = now()`,
      [studentId, counselorId, pattern, hours, day_type, confirmed]
    );

    if (Array.isArray(cells)) {
      await client.query('DELETE FROM weekly_cells WHERE student_id = $1', [studentId]);
      for (const c of cells) {
        if (typeof c.day === 'number' && typeof c.slot === 'number') {
          await client.query(
            `INSERT INTO weekly_cells (student_id, day, slot, subject, topic)
             VALUES ($1, $2, $3, $4, $5)`,
            [studentId, c.day, c.slot, c.subject || '', c.topic || '']
          );
        }
      }
    }

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Schedule save error:', err);
    res.status(500).json({ error: 'خطا در ذخیره برنامه' });
  } finally {
    client.release();
  }
});

// 11. دریافت پیام‌های چت
app.get('/api/messages/:studentId', authRequired, async (req, res) => {
  try {
    const studentId = req.params.studentId === 'me' ? req.user.id : req.params.studentId;
    if (req.user.role === 'student' && studentId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const { rows } = await pool.query(
      `SELECT m.id, m.student_id, m.sender_id, m.body, m.read_at, m.created_at,
              u.first_name AS sender_first_name, u.last_name AS sender_last_name, u.role AS sender_role
       FROM messages m
       JOIN users u ON u.id = m.sender_id
       WHERE m.student_id = $1
       ORDER BY m.created_at ASC`,
      [studentId]
    );
    res.json({ messages: rows });
  } catch (err) {
    res.status(500).json({ error: 'خطا در دریافت پیام‌ها' });
  }
});

// 12. ارسال پیام جدید
app.post('/api/messages/:studentId', authRequired, async (req, res) => {
  try {
    const studentId = req.params.studentId === 'me' ? req.user.id : req.params.studentId;
    if (req.user.role === 'student' && studentId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const { body } = req.body;
    if (!body || !body.trim()) {
      return res.status(400).json({ error: 'متن پیام نمی‌تواند خالی باشد' });
    }

    const { rows } = await pool.query(
      `INSERT INTO messages (student_id, sender_id, body)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [studentId, req.user.id, body.trim()]
    );
    res.status(201).json({ message: rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'خطا در ارسال پیام' });
  }
});

// 13. دریافت لیست آزمون‌ها
app.get('/api/exams/:studentId', authRequired, async (req, res) => {
  try {
    const studentId = req.params.studentId === 'me' ? req.user.id : req.params.studentId;
    if (req.user.role === 'student' && studentId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const { rows } = await pool.query(
      `SELECT * FROM exams WHERE student_id = $1 ORDER BY taken_at DESC NULLS LAST, created_at DESC`,
      [studentId]
    );
    res.json({ exams: rows });
  } catch (err) {
    res.status(500).json({ error: 'خطا در دریافت آزمون‌ها' });
  }
});

// 14. ثبت آزمون جدید
app.post('/api/exams/:studentId', authRequired, async (req, res) => {
  try {
    const studentId = req.params.studentId === 'me' ? req.user.id : req.params.studentId;
    if (req.user.role === 'student' && studentId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی غیرمجاز' });
    }

    const { title, subject = '', score = null, taken_at = null } = req.body;
    if (!title || !title.trim()) {
      return res.status(400).json({ error: 'عنوان آزمون الزامی است' });
    }

    const counselorId = req.user.role === 'counselor' ? req.user.id : null;
    const { rows } = await pool.query(
      `INSERT INTO exams (student_id, counselor_id, title, subject, score, taken_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [studentId, counselorId, title.trim(), subject.trim(), score, taken_at]
    );
    res.status(201).json({ exam: rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'خطا در ثبت آزمون' });
  }
});

app.listen(PORT, () => {
  console.log(`Dorbin backend running on http://localhost:${PORT}`);
});