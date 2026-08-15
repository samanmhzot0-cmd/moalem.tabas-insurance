# Maallem Insurance — production / 200 concurrent users

این نسخه روی همان پروژه موجود ساخته شده و برای رشد از حدود ۲۰۰ کاربر همزمان آماده‌تر است.

## رفع‌های اصلی
- احراز هویت با HttpOnly cookie؛ توکن در localStorage نگهداری نمی‌شود.
- Rate limit روی API و مسیرهای ورود/ثبت‌نام.
- PostgreSQL با connection pool.
- آپلود مستقیمِ یک‌باره: دیگر عکس برای `/photo-check` دوباره آپلود نمی‌شود.
- بررسی فنی تصویر با `sharp`.
- محدودیت ۶ عکس و ۱۲MB برای هر عکس.
- عکس اصلی بدون جایگزینی حفظ می‌شود.
- نسخه Preview با کیفیت ۸۸ و نسخه AI با کیفیت ۹۴ جداگانه ساخته می‌شوند.
- در صورت وجود Redis، پردازش نسخه‌ها به صف منتقل می‌شود تا فشار CPU درخواست‌های اصلی را کند نکند.
- در صورت وجود S3-compatible Object Storage، فایل‌ها خارج از دیسک سرور نگهداری می‌شوند.
- endpoint health برای مانیتورینگ.
- graceful shutdown.
- static assets با cache/etag.

## برای ۲۰۰ کاربر همزمان
برای production واقعی، PostgreSQL + Redis + private Object Storage را فعال کنید. حداقل ۲ Node instance پشت Load Balancer در زمان رشد توصیه می‌شود.

## اجرای محلی
1. `.env` را از `.env.example` بسازید.
2. PostgreSQL را آماده کنید.
3. `npm install`
4. `npm start`

## نکته مهم درباره AI
نسخه فعلی بررسی فنی/کیفی تصویر را انجام می‌دهد، اما تشخیص خسارت یا تصمیم بیمه‌ای را ادعا نمی‌کند. برای AI واقعی باید یک Vision Worker جدا با API key سمت سرور اضافه شود؛ کلید نباید در مرورگر قرار بگیرد.
