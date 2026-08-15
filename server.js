const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const sharp = require("sharp");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const { Queue, Worker } = require("bullmq");
const { S3Client, PutObjectCommand, GetObjectCommand } = require("@aws-sdk/client-s3");
const { getSignedUrl } = require("@aws-sdk/s3-request-presigner");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET;
const DATABASE_URL = process.env.DATABASE_URL;
const COOKIE_SECURE = process.env.COOKIE_SECURE !== "false";
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || `http://localhost:${PORT}`;
const MAX_PHOTOS = Number(process.env.MAX_PHOTOS || 6);
const MAX_PHOTO_MB = Number(process.env.MAX_PHOTO_MB || 12);
const PHOTO_MAX_BYTES = MAX_PHOTO_MB * 1024 * 1024;

if (!JWT_SECRET || JWT_SECRET.length < 32) throw new Error("JWT_SECRET must be at least 32 characters.");
if (!DATABASE_URL) throw new Error("DATABASE_URL is required.");

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: Number(process.env.DB_POOL_MAX || 20),
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 5000,
  ssl: process.env.DATABASE_SSL === "false" ? false : { rejectUnauthorized: false }
});

const localDir = path.join(__dirname, "uploads-private");
fs.mkdirSync(localDir, { recursive: true });

const s3Enabled = Boolean(process.env.S3_BUCKET && process.env.S3_ENDPOINT);
const s3 = s3Enabled ? new S3Client({
  region: process.env.S3_REGION || "auto",
  endpoint: process.env.S3_ENDPOINT,
  forcePathStyle: process.env.S3_FORCE_PATH_STYLE === "true",
  credentials: {
    accessKeyId: process.env.S3_ACCESS_KEY_ID,
    secretAccessKey: process.env.S3_SECRET_ACCESS_KEY
  }
}) : null;

const redisEnabled = Boolean(process.env.REDIS_URL);
let photoQueue = null;
let photoWorker = null;
if (redisEnabled) {
  photoQueue = new Queue("photo-processing", { connection: { url: process.env.REDIS_URL, maxRetriesPerRequest: null } });
}

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet({
  crossOriginResourcePolicy: { policy: "same-site" },
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'"],
      "img-src": ["'self'", "blob:", "data:"],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "base-uri": ["'self'"],
      "frame-ancestors": ["'none'"]
    }
  }
}));
app.use(cors({
  origin: FRONTEND_ORIGIN,
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 1000,
  standardHeaders: "draft-8",
  legacyHeaders: false
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  standardHeaders: "draft-8",
  legacyHeaders: false
});
app.use("/api", apiLimiter);

const upload = multer({
  storage: multer.diskStorage({
    destination: localDir,
    filename: (_, __, cb) => cb(null, `${crypto.randomUUID()}.upload`)
  }),
  limits: { fileSize: PHOTO_MAX_BYTES, files: MAX_PHOTOS },
  fileFilter: (_, file, cb) => cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype))
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      phone VARCHAR(40) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role VARCHAR(20) NOT NULL DEFAULT 'user',
      national VARCHAR(30) DEFAULT '',
      email VARCHAR(254) DEFAULT '',
      address TEXT DEFAULT '',
      birth DATE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS insurance_requests (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      type VARCHAR(80) NOT NULL,
      note VARCHAR(2000) DEFAULT '',
      status VARCHAR(80) NOT NULL DEFAULT 'در انتظار بررسی',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS photos (
      id UUID PRIMARY KEY,
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      original_key TEXT UNIQUE NOT NULL,
      preview_key TEXT,
      ai_key TEXT,
      original_name VARCHAR(255) NOT NULL,
      mime VARCHAR(80) NOT NULL,
      size BIGINT NOT NULL,
      width INTEGER,
      height INTEGER,
      status VARCHAR(40) NOT NULL DEFAULT 'processing',
      quality_note VARCHAR(500) DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_requests_user_created ON insurance_requests(user_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_photos_user_created ON photos(user_id, created_at DESC);
  `);
}

function uid() { return crypto.randomUUID(); }

function signToken(user) {
  return jwt.sign(
    { userId: user.id, role: user.role },
    JWT_SECRET,
    { expiresIn: "2h", issuer: "maallem-insurance", audience: "maallem-client" }
  );
}

function setAuthCookie(res, user) {
  res.cookie("maallem_token", signToken(user), {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: "lax",
    maxAge: 2 * 60 * 60 * 1000,
    path: "/"
  });
}

function auth(req, res, next) {
  try {
    const bearer = (req.headers.authorization || "").replace(/^Bearer\s+/, "");
    const token = req.cookies?.maallem_token || bearer;
    if (!token) throw new Error();
    req.auth = jwt.verify(token, JWT_SECRET, { issuer: "maallem-insurance", audience: "maallem-client" });
    next();
  } catch {
    res.status(401).json({ error: "نشست شما معتبر نیست." });
  }
}

function admin(req, res, next) {
  if (req.auth?.role !== "admin") return res.status(403).json({ error: "دسترسی مجاز نیست." });
  next();
}

async function storeObject(key, buffer, contentType) {
  if (s3Enabled) {
    await s3.send(new PutObjectCommand({
      Bucket: process.env.S3_BUCKET,
      Key: key,
      Body: buffer,
      ContentType: contentType,
      ServerSideEncryption: process.env.S3_SSE || undefined
    }));
    return;
  }
  const target = path.join(localDir, key);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, buffer);
}

async function getObjectStream(key) {
  if (s3Enabled) {
    const r = await s3.send(new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key }));
    return r.Body;
  }
  const file = path.join(localDir, key);
  if (!fs.existsSync(file)) return null;
  return fs.createReadStream(file);
}

async function signedObjectUrl(key) {
  if (!s3Enabled) return null;
  return getSignedUrl(s3, new GetObjectCommand({ Bucket: process.env.S3_BUCKET, Key: key }), { expiresIn: 300 });
}

async function processPhoto(photoId, sourcePath) {
  const meta = await sharp(sourcePath, { limitInputPixels: 40e6 }).metadata();
  const preview = await sharp(sourcePath, { limitInputPixels: 40e6 })
    .rotate()
    .resize({ width: 1600, height: 1600, fit: "inside", withoutEnlargement: true })
    .jpeg({ quality: 88, mozjpeg: true })
    .toBuffer();

  const ai = await sharp(sourcePath, { limitInputPixels: 40e6 })
    .rotate()
    .resize({ width: 2400, height: 2400, fit: "inside", withoutEnlargement: true })
    .jpeg({ quality: 94, mozjpeg: true })
    .toBuffer();

  const p = await pool.query("SELECT original_key FROM photos WHERE id=$1", [photoId]);
  if (!p.rowCount) return;

  const previewKey = `${photoId}/preview.jpg`;
  const aiKey = `${photoId}/ai.jpg`;
  await storeObject(previewKey, preview, "image/jpeg");
  await storeObject(aiKey, ai, "image/jpeg");

  await pool.query(
    `UPDATE photos SET preview_key=$1, ai_key=$2, width=$3, height=$4, status='ready',
      quality_note=$5 WHERE id=$6`,
    [previewKey, aiKey, meta.width || null, meta.height || null,
      "اصل تصویر حفظ شده است؛ نسخه‌های Preview و AI جداگانه ساخته شده‌اند.", photoId]
  );
}

if (photoQueue) {
  photoWorker = new Worker("photo-processing", async job => {
    await processPhoto(job.data.photoId, job.data.sourcePath);
    try { fs.rmSync(job.data.sourcePath, { force: true }); } catch {}
  }, { connection: { url: process.env.REDIS_URL, maxRetriesPerRequest: null }, concurrency: Number(process.env.PHOTO_WORKER_CONCURRENCY || 2) });
}

app.get("/api/health", async (_, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "up", queue: redisEnabled ? "up" : "disabled", storage: s3Enabled ? "object-storage" : "local" });
  } catch {
    res.status(503).json({ ok: false });
  }
});

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const { name, phone, password } = req.body || {};
    if (typeof name !== "string" || typeof phone !== "string" || typeof password !== "string" ||
      name.trim().length < 2 || password.length < 10) {
      return res.status(400).json({ error: "نام، شماره و رمز عبور معتبر لازم است." });
    }
    const user = { id: uid(), name: name.trim().slice(0, 120), phone: phone.trim().slice(0, 40), role: "user" };
    const hash = await bcrypt.hash(password, 12);
    await pool.query(
      "INSERT INTO users(id,name,phone,password_hash,role) VALUES($1,$2,$3,$4,$5)",
      [user.id, user.name, user.phone, hash, user.role]
    );
    setAuthCookie(res, user);
    res.json({ ok: true });
  } catch (e) {
    res.status(e.code === "23505" ? 409 : 500).json({ error: e.code === "23505" ? "این شماره قبلاً ثبت شده است." : "خطای داخلی سرور." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const r = await pool.query("SELECT * FROM users WHERE phone=$1", [String(req.body?.phone || "").trim()]);
  const u = r.rows[0];
  if (!u || !(await bcrypt.compare(String(req.body?.password || ""), u.password_hash)))
    return res.status(401).json({ error: "شماره یا رمز عبور نادرست است." });
  setAuthCookie(res, u);
  res.json({ ok: true });
});

app.post("/api/logout", auth, (req, res) => {
  res.clearCookie("maallem_token", { httpOnly: true, secure: COOKIE_SECURE, sameSite: "lax", path: "/" });
  res.json({ ok: true });
});

app.get("/api/me", auth, async (req, res) => {
  const r = await pool.query(
    "SELECT id,name,phone,role,national,email,address,birth FROM users WHERE id=$1",
    [req.auth.userId]
  );
  if (!r.rowCount) return res.status(404).json({ error: "کاربر پیدا نشد." });
  const u = r.rows[0];
  res.json({
    id: u.id, name: u.name, phone: u.phone, role: u.role,
    profile: { name: u.name, phone: u.phone, national: u.national || "", email: u.email || "",
      address: u.address || "", birth: u.birth ? String(u.birth).slice(0, 10) : "" }
  });
});

app.put("/api/me", auth, async (req, res) => {
  const birth = typeof req.body?.birth === "string" && /^\d{4}-\d{2}-\d{2}$/.test(req.body.birth) ? req.body.birth : null;
  await pool.query(
    "UPDATE users SET name=$1,national=$2,email=$3,address=$4,birth=$5 WHERE id=$6",
    [String(req.body?.name || "").trim().slice(0, 120), String(req.body?.national || "").trim().slice(0, 30),
      String(req.body?.email || "").trim().slice(0, 254), String(req.body?.address || "").trim().slice(0, 300),
      birth, req.auth.userId]
  );
  res.json({ ok: true });
});

app.post("/api/requests", auth, async (req, res) => {
  const type = String(req.body?.type || "").trim().slice(0, 80);
  const note = String(req.body?.note || "").slice(0, 2000);
  if (!type) return res.status(400).json({ error: "نوع بیمه لازم است." });
  const request = { id: uid(), type, note, status: "در انتظار بررسی" };
  await pool.query("INSERT INTO insurance_requests(id,user_id,type,note,status) VALUES($1,$2,$3,$4,$5)",
    [request.id, req.auth.userId, request.type, request.note, request.status]);
  res.json(request);
});

app.get("/api/requests", auth, async (req, res) => {
  const r = await pool.query(
    `SELECT id,type,note,status,created_at AS "createdAt"
     FROM insurance_requests WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.auth.userId]
  );
  res.json(r.rows);
});

app.post("/api/photos/check", auth, upload.single("photo"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "عکس معتبر دریافت نشد." });
  try {
    const meta = await sharp(req.file.path, { limitInputPixels: 40e6 }).metadata();
    const width = meta.width || 0, height = meta.height || 0;
    const ok = width >= 800 && height >= 600;
    fs.rmSync(req.file.path, { force: true });
    res.json({
      ok,
      technical: {
        width, height, format: meta.format,
        message: ok ? "کیفیت و ابعاد اولیه برای بررسی مناسب است." : "رزولوشن تصویر برای بررسی دقیق پایین است."
      },
      disclaimer: "این فقط بررسی فنی تصویر است و تأیید یا ارزیابی تخصصی بیمه‌ای نیست."
    });
  } catch {
    fs.rmSync(req.file.path, { force: true });
    res.status(400).json({ error: "فایل تصویر معتبر نیست." });
  }
});

app.post("/api/photos", auth, upload.array("photos", MAX_PHOTOS), async (req, res) => {
  const files = req.files || [];
  if (!files.length) return res.status(400).json({ error: "حداقل یک عکس انتخاب کنید." });
  const out = [];
  try {
    for (const f of files) {
      const meta = await sharp(f.path, { limitInputPixels: 40e6 }).metadata();
      if (!meta.width || !meta.height) throw new Error("INVALID_IMAGE");
      const photoId = uid();
      const originalKey = `${photoId}/original${path.extname(f.originalname || ".img").toLowerCase()}`;
      const buffer = fs.readFileSync(f.path);
      await storeObject(originalKey, buffer, f.mimetype);
      await pool.query(
        `INSERT INTO photos(id,user_id,original_key,original_name,mime,size,width,height,status)
         VALUES($1,$2,$3,$4,$5,$6,$7,$8,'processing')`,
        [photoId, req.auth.userId, originalKey, String(f.originalname).slice(0, 255), f.mimetype,
          buffer.length, meta.width || null, meta.height || null]
      );

      if (photoQueue) {
        await photoQueue.add("process", { photoId, sourcePath: f.path }, {
          attempts: 3, backoff: { type: "exponential", delay: 1000 }, removeOnComplete: 1000, removeOnFail: 1000
        });
      } else {
        await processPhoto(photoId, f.path);
        fs.rmSync(f.path, { force: true });
      }
      out.push({ id: photoId, name: f.originalname, status: redisEnabled ? "queued" : "ready" });
    }
    res.status(201).json(out);
  } catch (e) {
    for (const f of files) fs.rmSync(f.path, { force: true });
    console.error(e);
    res.status(400).json({ error: "یکی از تصاویر قابل پردازش نیست." });
  }
});

app.get("/api/photos", auth, async (req, res) => {
  const r = await pool.query(
    `SELECT id,original_name AS "originalName",mime,size,width,height,status,created_at AS "createdAt",
      preview_key,ai_key FROM photos WHERE user_id=$1 ORDER BY created_at DESC LIMIT 100`,
    [req.auth.userId]
  );
  const rows = [];
  for (const p of r.rows) {
    rows.push({
      ...p,
      previewUrl: p.preview_key ? await signedObjectUrl(p.preview_key) : null
    });
  }
  res.json(rows);
});

app.get("/api/photos/:id/original", auth, async (req, res) => {
  const r = await pool.query("SELECT original_key,mime FROM photos WHERE id=$1 AND user_id=$2",
    [req.params.id, req.auth.userId]);
  if (!r.rowCount) return res.status(404).end();
  if (s3Enabled) return res.redirect(await signedObjectUrl(r.rows[0].original_key));
  const stream = await getObjectStream(r.rows[0].original_key);
  if (!stream) return res.status(404).end();
  res.type(r.rows[0].mime); stream.pipe(res);
});

app.get("/api/admin/requests", auth, admin, async (_, res) => {
  const r = await pool.query(
    `SELECT r.id,r.type,r.note,r.status,r.created_at AS "createdAt",u.name,u.phone
     FROM insurance_requests r JOIN users u ON u.id=r.user_id
     ORDER BY r.created_at DESC LIMIT 1000`
  );
  res.json(r.rows);
});

app.use(express.static(path.join(__dirname, "public"), {
  maxAge: process.env.NODE_ENV === "production" ? "1h" : 0,
  etag: true
}));

app.use((err, req, res, next) => {
  if (err?.code === "LIMIT_FILE_SIZE") return res.status(413).json({ error: `حجم هر عکس حداکثر ${MAX_PHOTO_MB}MB است.` });
  if (err instanceof multer.MulterError) return res.status(400).json({ error: "آپلود فایل نامعتبر است." });
  console.error(err);
  res.status(500).json({ error: "خطای داخلی سرور." });
});

async function shutdown() {
  try { await photoWorker?.close(); } catch {}
  try { await photoQueue?.close(); } catch {}
  await pool.end();
  process.exit(0);
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

initDb()
  .then(() => app.listen(PORT, () => console.log(`Maallem Insurance on :${PORT}`)))
  .catch(err => { console.error("DB init failed", err); process.exit(1); });
