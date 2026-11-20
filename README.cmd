# سرور Backend پلتفرم دور-بین (Node.js + Express + PostgreSQL)

این پروژه دقیقاً بر اساس جدول‌های دیتابیس شما (`users`, `sessions`, `study_schedules`, `weekly_cells`, `messages`, `exams`) ساخته شده است.

## مراحل راه‌اندازی روی کامپیوتر یا سرور

1. مطمئن شوید **Node.js** (نسخه 18 به بالا) نصب است.
2. فایل‌ها را از حالت فشرده خارج کنید و وارد پوشه شوید.
3. یک فایل به نام `.env` بسازید (می‌توانید `.env.example` را کپی کنید و اسمش را `.env` بگذارید) و آدرس اتصال دیتابیس خود را داخل آن قرار دهید:
   ```env
   PORT=4000
   DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@YOUR_HOST:5432/postgres
   CORS_ORIGIN=*
   ```
4. پکیج‌ها را نصب کنید:
   ```bash
   npm install
   ```
5. سرور را اجرا کنید:
   ```bash
   npm start
   ```
6. برای تست، مرورگر را باز کنید و بروید به:
   `http://localhost:4000/api/health`
   اگر `{"ok": true, ...}` دیدید، یعنی سرور به دیتابیس شما وصل شده است!

## آدرس‌های API آماده شده

- `GET /api/health` — تست اتصال سرور و دیتابیس
- `POST /api/auth/register` — ثبت‌نام (`phone`, `password`, `first_name`, `last_name`, `role`)
- `POST /api/auth/login` — ورود (`phone`, `password`) و دریافت `token`
- `POST /api/auth/logout` — خروج (نیاز به هدر `Authorization: Bearer TOKEN`)
- `GET /api/me` — دریافت اطلاعات کاربر لاگین‌شده
- `GET /api/students` — لیست دانش‌آموزان (برای مشاور، موسسه و ادمین)
- `GET /api/schedule/:studentId` — دریافت برنامه و خانه‌های جدول هفتگی (`me` برای خود دانش‌آموز)
- `PUT /api/schedule/:studentId` — ذخیره/بروزرسانی برنامه و خانه‌های جدول هفتگی
- `GET /api/messages/:studentId` — دریافت پیام‌های چت
- `POST /api/messages/:studentId` — ارسال پیام جدید (`body`)
- `GET /api/exams/:studentId` — دریافت لیست آزمون‌ها
- `POST /api/exams/:studentId` — ثبت آزمون جدید (`title`, `subject`, `score`, `taken_at`)
