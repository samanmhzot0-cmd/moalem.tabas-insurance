const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET_IN_PRODUCTION";

app.use(cors());
app.use(express.json());

const dataDir = path.join(__dirname, "data");
const uploadDir = path.join(__dirname, "uploads");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const dbFile = path.join(dataDir, "db.json");
if (!fs.existsSync(dbFile)) {
  fs.writeFileSync(dbFile, JSON.stringify({ users: [], requests: [], policies: [] }, null, 2));
}

function db() { return JSON.parse(fs.readFileSync(dbFile, "utf8")); }
function saveDb(x) { fs.writeFileSync(dbFile, JSON.stringify(x, null, 2)); }

function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || "").replace("Bearer ", "");
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ error: "نشست شما معتبر نیست." });
  }
}

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, "_");
    cb(null, `${req.userId}-${Date.now()}-${safe}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    cb(null, /^image\/(jpeg|png|webp)$/.test(file.mimetype));
  }
});

app.use("/uploads", express.static(uploadDir));
app.use(express.static(path.join(__dirname, "public")));

app.post("/api/register", async (req, res) => {
  const { name, phone, password } = req.body;
  if (!name || !phone || !password || password.length < 6)
    return res.status(400).json({ error: "نام، شماره موبایل و رمز حداقل ۶ کاراکتری لازم است." });

  const data = db();
  if (data.users.some(u => u.phone === phone))
    return res.status(409).json({ error: "این شماره قبلاً ثبت شده است." });

  const user = {
    id: cryptoRandom(),
    name, phone,
    passwordHash: await bcrypt.hash(password, 12),
    profile: { name, phone, national: "", email: "", address: "", birth: "" },
    photos: []
  };
  data.users.push(user);
  saveDb(data);

  res.json({ token: jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" }) });
});

app.post("/api/login", async (req, res) => {
  const { phone, password } = req.body;
  const data = db();
  const user = data.users.find(u => u.phone === phone);
  if (!user || !(await bcrypt.compare(password, user.passwordHash)))
    return res.status(401).json({ error: "شماره یا رمز عبور نادرست است." });

  res.json({ token: jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: "7d" }) });
});

app.get("/api/me", auth, (req, res) => {
  const data = db();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "کاربر پیدا نشد." });
  const { passwordHash, ...safe } = user;
  res.json(safe);
});

app.put("/api/me", auth, (req, res) => {
  const data = db();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "کاربر پیدا نشد." });

  user.profile = {
    ...user.profile,
    ...req.body
  };
  user.name = user.profile.name || user.name;
  saveDb(data);
  res.json({ ok: true });
});

app.post("/api/requests", auth, (req, res) => {
  const { type, note = "" } = req.body;
  if (!type) return res.status(400).json({ error: "نوع بیمه الزامی است." });

  const data = db();
  const request = {
    id: cryptoRandom(),
    userId: req.userId,
    type, note,
    status: "در انتظار بررسی",
    createdAt: new Date().toISOString()
  };
  data.requests.push(request);
  saveDb(data);
  res.json(request);
});

app.get("/api/requests", auth, (req, res) => {
  const data = db();
  res.json(data.requests.filter(r => r.userId === req.userId));
});

app.get("/api/policies", auth, (req, res) => {
  const data = db();
  res.json(data.policies.filter(p => p.userId === req.userId));
});

app.post("/api/body-photos", auth, upload.array("photos", 6), (req, res) => {
  const data = db();
  const user = data.users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ error: "کاربر پیدا نشد." });

  const items = req.files.map(f => ({
    id: cryptoRandom(),
    path: `/uploads/${f.filename}`,
    originalName: f.originalname,
    createdAt: new Date().toISOString()
  }));
  user.photos.push(...items);
  saveDb(data);
  res.json(items);
});

app.get("/api/admin/requests", auth, (req, res) => {
  // برای دمو فقط: در پروژه واقعی نقش admin جداگانه اضافه کنید.
  const data = db();
  res.json(data.requests);
});

function cryptoRandom() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

app.listen(PORT, () => console.log(`Server: http://localhost:${PORT}`));
