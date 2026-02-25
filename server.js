const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const path = require("path");
const { createClient } = require("@libsql/client");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const FRONTEND_DIR = path.resolve(__dirname, "./streak-frontend");
app.use(express.static(FRONTEND_DIR));

const db = createClient({
  url: process.env.TURSO_DATABASE_URL || "your_turso_database_url_here",
  authToken: process.env.TURSO_AUTH_TOKEN || "your_turso_auth_token_here",
});

const PORT = Number(process.env.PORT || 5000);
const SESSION_TTL_DAYS = Number(process.env.SESSION_TTL_DAYS || 0);
const NEVER_EXPIRES_ISO = "9999-12-31T23:59:59.999Z";
const EMAIL_OTP_TTL_MINUTES = Number(process.env.EMAIL_OTP_TTL_MINUTES || 10);
const RESET_PASSWORD_TOKEN_TTL_MINUTES = Number(
  process.env.RESET_PASSWORD_TOKEN_TTL_MINUTES || 30
);
const HABIT_NAME_MAX_LENGTH = Number(process.env.HABIT_NAME_MAX_LENGTH || 48);

const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";
const MAIL_FROM = process.env.MAIL_FROM || GMAIL_USER;
const FRONTEND_RESET_URL =
  process.env.FRONTEND_RESET_URL ||
  "http://127.0.0.1:5500/streak-frontend/reset-password.html";

let mailTransporter = null;

function isGmailAddress(email) {
  return /^[^\s@]+@gmail\.com$/i.test(String(email || "").trim());
}

function getMailTransporter() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    throw new Error("Email service is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD in .env");
  }

  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: GMAIL_USER,
        pass: GMAIL_APP_PASSWORD,
      },
    });
  }

  return mailTransporter;
}

function createEmailOtp() {
  const otp = String(Math.floor(Math.random() * 1_000_000)).padStart(6, "0");
  const otpHash = crypto.createHash("sha256").update(otp).digest("hex");
  const expiresAt = new Date(
    Date.now() + EMAIL_OTP_TTL_MINUTES * 60 * 1000
  ).toISOString();

  return { otp, otpHash, expiresAt };
}

function createPasswordResetToken() {
  const rawToken = crypto.randomBytes(32).toString("hex");
  const tokenHash = crypto.createHash("sha256").update(rawToken).digest("hex");
  const expiresAt = new Date(
    Date.now() + RESET_PASSWORD_TOKEN_TTL_MINUTES * 60 * 1000
  ).toISOString();

  return { rawToken, tokenHash, expiresAt };
}

async function sendEmailVerificationOtp({ email, name, otp }) {
  const transporter = getMailTransporter();

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: "Your Streak Tracker verification OTP",
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #1d2a29;">
        <h2 style="margin-bottom: 8px;">Hi ${name},</h2>
        <p style="margin-top: 0;">Use this OTP to verify your Streak Tracker account:</p>
        <p style="font-size: 30px; font-weight: 700; letter-spacing: 4px; margin: 10px 0;">${otp}</p>
        <p style="font-size: 13px; color: #58706d;">This OTP expires in ${EMAIL_OTP_TTL_MINUTES} minutes.</p>
      </div>
    `,
  });
}

async function sendPasswordResetEmail({ email, name, rawToken }) {
  const transporter = getMailTransporter();
  const resetLink = `${FRONTEND_RESET_URL}?token=${encodeURIComponent(rawToken)}`;

  await transporter.sendMail({
    from: MAIL_FROM,
    to: email,
    subject: "Reset your Streak Tracker password",
    html: `
      <div style="font-family: Arial, sans-serif; line-height: 1.5; color: #1d2a29;">
        <h2 style="margin-bottom: 8px;">Hi ${name},</h2>
        <p style="margin-top: 0;">We received a request to reset your password.</p>
        <p>
          <a href="${resetLink}" style="display:inline-block;background:#0f8a73;color:#fff;padding:10px 16px;border-radius:8px;text-decoration:none;">
            Reset Password
          </a>
        </p>
        <p style="font-size: 13px; color: #58706d;">This link expires in ${RESET_PASSWORD_TOKEN_TTL_MINUTES} minutes.</p>
        <p style="font-size: 13px; color: #58706d;">If button does not work, copy this URL:</p>
        <p style="font-size: 13px; word-break: break-all; color: #58706d;">${resetLink}</p>
      </div>
    `,
  });
}

function formatLocalDate(date) {
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}

function normalizeYmdInput(value) {
  const raw = String(value || "").trim();
  if (/^\d{4}-\d{2}-\d{2}T/.test(raw)) {
    return raw.slice(0, 10);
  }
  return raw;
}

function parseYmdToDate(ymd) {
  const normalized = normalizeYmdInput(ymd);
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(normalized);
  if (!match) {
    return null;
  }

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const date = new Date(year, month - 1, day);

  if (formatLocalDate(date) !== `${match[1]}-${match[2]}-${match[3]}`) {
    return null;
  }

  return date;
}

function isValidTimeHHMM(value) {
  return /^([01]\d|2[0-3]):([0-5]\d)$/.test(String(value || "").trim());
}

function parseLogs(logsValue) {
  try {
    const parsed = JSON.parse(logsValue || "[]");
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

function normalizeUser(row) {
  return {
    id: Number(row.id),
    name: row.name,
    email: row.email,
    isVerified: Number(row.isVerified || 0) === 1,
  };
}

function normalizeHabit(row) {
  const parsedStartDate = parseYmdToDate(row.startDate);

  return {
    id: Number(row.id),
    userId: Number(row.userId),
    name: row.name,
    logs: parseLogs(row.logs),
    currentStreak: Number(row.currentStreak || 0),
    longestStreak: Number(row.longestStreak || 0),
    targetDays: Number(row.targetDays || 0),
    startDate: parsedStartDate
      ? formatLocalDate(parsedStartDate)
      : String(row.startDate || "").trim(),
    archived: Number(row.archived || 0) === 1,
    archivedAt: row.archivedAt || null,
    reminderEnabled: Number(row.reminderEnabled || 0) === 1,
    reminderTime: row.reminderTime || null,
    createdAt: row.createdAt || null,
  };
}

function getHabitStartDate(habit) {
  if (habit && habit.startDate) {
    const fromStartDate = parseYmdToDate(habit.startDate);
    if (fromStartDate) {
      return fromStartDate;
    }
  }

  if (habit && habit.createdAt) {
    const createdAtDate = new Date(habit.createdAt);
    if (!Number.isNaN(createdAtDate.getTime())) {
      return new Date(
        createdAtDate.getFullYear(),
        createdAtDate.getMonth(),
        createdAtDate.getDate()
      );
    }
  }

  const logs = Array.isArray(habit?.logs) ? [...habit.logs] : [];
  if (logs.length > 0) {
    logs.sort();
    const firstLogDate = parseYmdToDate(logs[0]);
    if (firstLogDate) {
      return firstLogDate;
    }
  }

  const now = new Date();
  return new Date(now.getFullYear(), now.getMonth(), now.getDate());
}

function getHabitEndDate(habit) {
  const targetDays = Number(habit?.targetDays || 0);
  if (!Number.isInteger(targetDays) || targetDays <= 0) {
    return null;
  }

  const startDate = getHabitStartDate(habit);
  const endDate = new Date(startDate);
  endDate.setDate(endDate.getDate() + targetDays - 1);
  return endDate;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPasswordHash) {
  const [salt, savedHash] = String(storedPasswordHash || "").split(":");
  if (!salt || !savedHash) {
    return false;
  }

  const candidateHash = crypto.scryptSync(password, salt, 64).toString("hex");
  const savedHashBuffer = Buffer.from(savedHash, "hex");
  const candidateHashBuffer = Buffer.from(candidateHash, "hex");

  if (savedHashBuffer.length !== candidateHashBuffer.length) {
    return false;
  }

  return crypto.timingSafeEqual(savedHashBuffer, candidateHashBuffer);
}

function createSessionToken() {
  return crypto.randomBytes(48).toString("hex");
}

function createExpiryDateIso(daysFromNow) {
  if (!Number.isFinite(daysFromNow) || daysFromNow <= 0) {
    return NEVER_EXPIRES_ISO;
  }

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + daysFromNow);
  return expiresAt.toISOString();
}

async function createSession(userId) {
  const token = createSessionToken();
  const expiresAt = createExpiryDateIso(SESSION_TTL_DAYS);

  await db.execute({
    sql: "INSERT INTO sessions (token, userId, expiresAt) VALUES (?, ?, ?)",
    args: [token, userId, expiresAt],
  });

  return { token, expiresAt };
}

async function getUserByToken(token) {
  const sessionResult = await db.execute({
    sql: `
      SELECT users.id, users.name, users.email, users.isVerified, sessions.expiresAt
      FROM sessions
      INNER JOIN users ON users.id = sessions.userId
      WHERE sessions.token = ?
      LIMIT 1
    `,
    args: [token],
  });

  if (sessionResult.rows.length === 0) {
    return null;
  }

  const row = sessionResult.rows[0];

  if (!row.expiresAt) {
    await db.execute({
      sql: "DELETE FROM sessions WHERE token = ?",
      args: [token],
    });
    return null;
  }

  const isNeverExpiring = String(row.expiresAt) === NEVER_EXPIRES_ISO;

  if (!isNeverExpiring && new Date(row.expiresAt) < new Date()) {
    await db.execute({
      sql: "DELETE FROM sessions WHERE token = ?",
      args: [token],
    });
    return null;
  }

  if (Number(row.isVerified || 0) !== 1) {
    await db.execute({
      sql: "DELETE FROM sessions WHERE token = ?",
      args: [token],
    });
    return null;
  }

  return normalizeUser(row);
}

async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    if (!authHeader.startsWith("Bearer ")) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const token = authHeader.slice(7).trim();
    if (!token) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const user = await getUserByToken(token);
    if (!user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    req.auth = { token, user };
    return next();
  } catch {
    return res.status(500).json({ error: "Authentication failed" });
  }
}

async function ensureUsersSchema() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      passwordHash TEXT NOT NULL,
      isVerified INTEGER NOT NULL DEFAULT 0,
      emailOtpHash TEXT,
      emailOtpExpiresAt TEXT,
      resetPasswordTokenHash TEXT,
      resetPasswordExpiresAt TEXT,
      verifiedAt TEXT,
      createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const tableInfo = await db.execute("PRAGMA table_info(users)");
  const columns = new Set(tableInfo.rows.map((column) => column.name));
  let markExistingAsVerified = false;

  if (!columns.has("isVerified")) {
    await db.execute("ALTER TABLE users ADD COLUMN isVerified INTEGER NOT NULL DEFAULT 0");
    markExistingAsVerified = true;
  }

  if (!columns.has("emailOtpHash")) {
    await db.execute("ALTER TABLE users ADD COLUMN emailOtpHash TEXT");
  }

  if (!columns.has("emailOtpExpiresAt")) {
    await db.execute("ALTER TABLE users ADD COLUMN emailOtpExpiresAt TEXT");
  }

  if (!columns.has("resetPasswordTokenHash")) {
    await db.execute("ALTER TABLE users ADD COLUMN resetPasswordTokenHash TEXT");
  }

  if (!columns.has("resetPasswordExpiresAt")) {
    await db.execute("ALTER TABLE users ADD COLUMN resetPasswordExpiresAt TEXT");
  }

  if (!columns.has("verifiedAt")) {
    await db.execute("ALTER TABLE users ADD COLUMN verifiedAt TEXT");
  }

  if (markExistingAsVerified) {
    await db.execute("UPDATE users SET isVerified = 1 WHERE isVerified = 0");
  }
}

async function ensureHabitsSchema() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS habits (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      name TEXT NOT NULL,
      logs TEXT NOT NULL DEFAULT '[]',
      currentStreak INTEGER NOT NULL DEFAULT 0,
      longestStreak INTEGER NOT NULL DEFAULT 0,
      targetDays INTEGER NOT NULL DEFAULT 0,
      startDate TEXT,
      archived INTEGER NOT NULL DEFAULT 0,
      archivedAt TEXT,
      reminderEnabled INTEGER NOT NULL DEFAULT 0,
      reminderTime TEXT,
      createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const tableInfo = await db.execute("PRAGMA table_info(habits)");
  const columns = new Set(tableInfo.rows.map((column) => column.name));

  if (!columns.has("userId")) {
    await db.execute("ALTER TABLE habits ADD COLUMN userId INTEGER");
  }

  if (!columns.has("targetDays")) {
    await db.execute("ALTER TABLE habits ADD COLUMN targetDays INTEGER NOT NULL DEFAULT 0");
  }

  if (!columns.has("createdAt")) {
    await db.execute("ALTER TABLE habits ADD COLUMN createdAt TEXT");
  }

  if (!columns.has("startDate")) {
    await db.execute("ALTER TABLE habits ADD COLUMN startDate TEXT");
  }

  if (!columns.has("archived")) {
    await db.execute("ALTER TABLE habits ADD COLUMN archived INTEGER NOT NULL DEFAULT 0");
  }

  if (!columns.has("archivedAt")) {
    await db.execute("ALTER TABLE habits ADD COLUMN archivedAt TEXT");
  }

  if (!columns.has("reminderEnabled")) {
    await db.execute("ALTER TABLE habits ADD COLUMN reminderEnabled INTEGER NOT NULL DEFAULT 0");
  }

  if (!columns.has("reminderTime")) {
    await db.execute("ALTER TABLE habits ADD COLUMN reminderTime TEXT");
  }

  await db.execute(`
    UPDATE habits
    SET createdAt = COALESCE(createdAt, CURRENT_TIMESTAMP)
    WHERE createdAt IS NULL OR createdAt = ''
  `);

  await db.execute(`
    UPDATE habits
    SET archived = COALESCE(archived, 0)
    WHERE archived IS NULL
  `);

  await db.execute({
    sql: `
      UPDATE habits
      SET startDate = COALESCE(startDate, substr(createdAt, 1, 10), ?)
      WHERE startDate IS NULL OR startDate = ''
    `,
    args: [formatLocalDate(new Date())],
  });

  await db.execute(`
    UPDATE habits
    SET startDate = substr(trim(startDate), 1, 10)
    WHERE trim(startDate) LIKE '____-__-__T%'
  `);
}

async function initDB() {
  try {
    await ensureUsersSchema();

    await db.execute(`
      CREATE TABLE IF NOT EXISTS sessions (
        token TEXT PRIMARY KEY,
        userId INTEGER NOT NULL,
        expiresAt TEXT NOT NULL,
        createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await ensureHabitsSchema();

    if (!Number.isFinite(SESSION_TTL_DAYS) || SESSION_TTL_DAYS <= 0) {
      await db.execute({
        sql: `
          UPDATE sessions
          SET expiresAt = ?
          WHERE expiresAt <> ? AND expiresAt >= ?
        `,
        args: [NEVER_EXPIRES_ISO, NEVER_EXPIRES_ISO, new Date().toISOString()],
      });
    }

    await db.execute({
      sql: "DELETE FROM sessions WHERE expiresAt <> ? AND expiresAt < ?",
      args: [NEVER_EXPIRES_ISO, new Date().toISOString()],
    });

    console.log("Turso database connected and schema ready");
  } catch (err) {
    console.error("Turso DB error:", err.message);
    process.exit(1);
  }
}

async function issueEmailOtpForUser({ userId, name, email }) {
  const otpData = createEmailOtp();

  await db.execute({
    sql: `
      UPDATE users
      SET emailOtpHash = ?, emailOtpExpiresAt = ?, isVerified = 0
      WHERE id = ?
    `,
    args: [otpData.otpHash, otpData.expiresAt, userId],
  });

  await sendEmailVerificationOtp({
    email,
    name,
    otp: otpData.otp,
  });
}

async function issuePasswordResetForUser({ userId, name, email }) {
  const reset = createPasswordResetToken();

  await db.execute({
    sql: `
      UPDATE users
      SET resetPasswordTokenHash = ?, resetPasswordExpiresAt = ?
      WHERE id = ?
    `,
    args: [reset.tokenHash, reset.expiresAt, userId],
  });

  await sendPasswordResetEmail({
    email,
    name,
    rawToken: reset.rawToken,
  });
}

async function handleResendVerificationOtp(email) {
  const result = await db.execute({
    sql: "SELECT id, name, email, isVerified FROM users WHERE email = ? LIMIT 1",
    args: [email],
  });

  if (result.rows.length === 0) {
    return { message: "If this account exists, OTP has been sent." };
  }

  const user = result.rows[0];

  if (Number(user.isVerified || 0) === 1) {
    return { message: "Email already verified. Please login." };
  }

  await issueEmailOtpForUser({
    userId: Number(user.id),
    name: String(user.name || "User"),
    email,
  });

  return { message: "OTP sent to your email." };
}

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = String(req.body?.name || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    if (!name || !email || !password) {
      return res.status(400).json({ error: "Name, email, and password are required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const existingUserResult = await db.execute({
      sql: "SELECT id, name, email, isVerified FROM users WHERE email = ? LIMIT 1",
      args: [email],
    });

    const passwordHash = hashPassword(password);

    if (existingUserResult.rows.length > 0) {
      const existing = existingUserResult.rows[0];

      if (Number(existing.isVerified || 0) === 1) {
        return res.status(409).json({ error: "Email already in use" });
      }

      await db.execute({
        sql: "UPDATE users SET name = ?, passwordHash = ? WHERE id = ?",
        args: [name, passwordHash, existing.id],
      });

      await issueEmailOtpForUser({ userId: Number(existing.id), name, email });

      return res.json({
        message: "OTP sent to your email. Verify before login.",
        email,
      });
    }

    const createdUserResult = await db.execute({
      sql: `
        INSERT INTO users (name, email, passwordHash, isVerified)
        VALUES (?, ?, ?, 0)
        RETURNING id, name, email, isVerified
      `,
      args: [name, email, passwordHash],
    });

    const user = normalizeUser(createdUserResult.rows[0]);

    await issueEmailOtpForUser({
      userId: user.id,
      name: user.name,
      email: user.email,
    });

    return res.status(201).json({
      message: "Registration successful. OTP sent to your email.",
      email: user.email,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/resend-verification-otp", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    const result = await handleResendVerificationOtp(email);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// Backward-compatible alias route
app.post("/api/auth/resend-verification", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    const result = await handleResendVerificationOtp(email);
    return res.json(result);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/verify-otp", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const otp = String(req.body?.otp || "").trim();

    if (!email || !otp) {
      return res.status(400).json({ error: "Email and OTP are required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const userResult = await db.execute({
      sql: `
        SELECT id, isVerified, emailOtpHash, emailOtpExpiresAt
        FROM users
        WHERE email = ?
        LIMIT 1
      `,
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid email or OTP" });
    }

    const user = userResult.rows[0];

    if (Number(user.isVerified || 0) === 1) {
      return res.json({ message: "Email already verified" });
    }

    if (!user.emailOtpHash || !user.emailOtpExpiresAt) {
      return res.status(400).json({ error: "OTP not requested. Please resend OTP." });
    }

    if (new Date(user.emailOtpExpiresAt) < new Date()) {
      return res.status(400).json({ error: "OTP expired. Please resend OTP." });
    }

    const candidateHash = crypto.createHash("sha256").update(otp).digest("hex");
    const savedHashBuffer = Buffer.from(String(user.emailOtpHash), "hex");
    const candidateHashBuffer = Buffer.from(candidateHash, "hex");

    if (
      savedHashBuffer.length !== candidateHashBuffer.length ||
      !crypto.timingSafeEqual(savedHashBuffer, candidateHashBuffer)
    ) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    await db.execute({
      sql: `
        UPDATE users
        SET isVerified = 1,
            verifiedAt = ?,
            emailOtpHash = NULL,
            emailOtpExpiresAt = NULL
        WHERE id = ?
      `,
      args: [new Date().toISOString(), user.id],
    });

    return res.json({ message: "Email verified successfully" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/forgot-password", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();

    if (!email) {
      return res.status(400).json({ error: "Email is required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    const genericMessage =
      "If this account exists, password reset instructions have been sent.";

    const userResult = await db.execute({
      sql: `
        SELECT id, name, email, isVerified
        FROM users
        WHERE email = ?
        LIMIT 1
      `,
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.json({ message: genericMessage });
    }

    const user = userResult.rows[0];

    if (Number(user.isVerified || 0) === 1) {
      await issuePasswordResetForUser({
        userId: Number(user.id),
        name: String(user.name || "User"),
        email: String(user.email || email),
      });
    } else {
      await issueEmailOtpForUser({
        userId: Number(user.id),
        name: String(user.name || "User"),
        email: String(user.email || email),
      });
    }

    return res.json({ message: genericMessage });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const password = String(req.body?.password || "");

    if (!token || !password) {
      return res.status(400).json({ error: "Token and password are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const userResult = await db.execute({
      sql: `
        SELECT id, resetPasswordExpiresAt
        FROM users
        WHERE resetPasswordTokenHash = ?
        LIMIT 1
      `,
      args: [tokenHash],
    });

    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: "Invalid reset token" });
    }

    const user = userResult.rows[0];

    if (!user.resetPasswordExpiresAt || new Date(user.resetPasswordExpiresAt) < new Date()) {
      return res.status(400).json({ error: "Reset token expired" });
    }

    const passwordHash = hashPassword(password);

    await db.execute({
      sql: `
        UPDATE users
        SET passwordHash = ?,
            resetPasswordTokenHash = NULL,
            resetPasswordExpiresAt = NULL
        WHERE id = ?
      `,
      args: [passwordHash, user.id],
    });

    await db.execute({
      sql: "DELETE FROM sessions WHERE userId = ?",
      args: [user.id],
    });

    return res.json({ message: "Password reset successful. Please login again." });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const password = String(req.body?.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password are required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    const userResult = await db.execute({
      sql: "SELECT id, name, email, passwordHash, isVerified FROM users WHERE email = ? LIMIT 1",
      args: [email],
    });

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    const row = userResult.rows[0];
    const isValid = verifyPassword(password, row.passwordHash);
    if (!isValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    if (Number(row.isVerified || 0) !== 1) {
      return res.status(403).json({
        error: "Please verify your email with OTP before login",
        code: "EMAIL_NOT_VERIFIED",
      });
    }

    const user = normalizeUser(row);
    const session = await createSession(user.id);

    return res.json({
      message: "Login successful",
      token: session.token,
      expiresAt: session.expiresAt,
      user,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/auth/me", requireAuth, async (req, res) => {
  return res.json({ user: req.auth.user });
});

app.post("/api/auth/logout", requireAuth, async (req, res) => {
  try {
    await db.execute({
      sql: "DELETE FROM sessions WHERE token = ?",
      args: [req.auth.token],
    });
    return res.json({ message: "Logged out" });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/habits", requireAuth, async (req, res) => {
  try {
    const result = await db.execute({
      sql: "SELECT * FROM habits WHERE userId = ? ORDER BY id DESC",
      args: [req.auth.user.id],
    });

    return res.json(result.rows.map(normalizeHabit));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/habits", requireAuth, async (req, res) => {
  try {
    const name = String(req.body?.name || "")
      .replace(/\s+/g, " ")
      .trim();
    const targetDaysRaw = req.body?.targetDays;
    let targetDays = 0;
    const startDateRaw = String(req.body?.startDate || "").trim();
    const reminderEnabled = Boolean(req.body?.reminderEnabled);
    const reminderTime = String(req.body?.reminderTime || "").trim();

    if (!name) {
      return res.status(400).json({ error: "Habit name is required" });
    }
    if (name.length > HABIT_NAME_MAX_LENGTH) {
      return res.status(400).json({
        error: `Habit name must be ${HABIT_NAME_MAX_LENGTH} characters or less`,
      });
    }

    const hasTargetDays =
      targetDaysRaw !== undefined &&
      targetDaysRaw !== null &&
      String(targetDaysRaw).trim() !== "";

    if (hasTargetDays) {
      const parsedTargetDays = Number(targetDaysRaw);
      if (!Number.isInteger(parsedTargetDays) || parsedTargetDays < 1 || parsedTargetDays > 3650) {
        return res
          .status(400)
          .json({ error: "targetDays must be an integer between 1 and 3650" });
      }
      targetDays = parsedTargetDays;
    }

    const resolvedStartDate = startDateRaw || formatLocalDate(new Date());
    if (!parseYmdToDate(resolvedStartDate)) {
      return res.status(400).json({ error: "startDate must be in YYYY-MM-DD format" });
    }

    if (reminderEnabled && !isValidTimeHHMM(reminderTime)) {
      return res.status(400).json({ error: "reminderTime must be in HH:MM format" });
    }

    const result = await db.execute({
      sql: `
        INSERT INTO habits (
          userId,
          name,
          logs,
          currentStreak,
          longestStreak,
          targetDays,
          startDate,
          reminderEnabled,
          reminderTime,
          createdAt
        )
        VALUES (?, ?, '[]', 0, 0, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        RETURNING *
      `,
      args: [
        req.auth.user.id,
        name,
        targetDays,
        resolvedStartDate,
        reminderEnabled ? 1 : 0,
        reminderEnabled ? reminderTime : null,
      ],
    });

    return res.status(201).json(normalizeHabit(result.rows[0]));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/habits/:id/mark", requireAuth, async (req, res) => {
  try {
    const habitId = Number(req.params.id);

    if (!Number.isInteger(habitId) || habitId <= 0) {
      return res.status(400).json({ error: "Invalid habit id" });
    }

    const result = await db.execute({
      sql: "SELECT * FROM habits WHERE id = ? AND userId = ? LIMIT 1",
      args: [habitId, req.auth.user.id],
    });

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Habit not found" });
    }

    const habit = normalizeHabit(result.rows[0]);
    if (habit.archived) {
      return res.status(400).json({ error: "Archived streak cannot be marked." });
    }

    const logs = Array.from(
      new Set(
        (Array.isArray(habit.logs) ? habit.logs : [])
          .map((day) => normalizeYmdInput(day))
          .filter((day) => Boolean(parseYmdToDate(day)))
      )
    );
    let currentStreak = habit.currentStreak;
    let longestStreak = habit.longestStreak;

    const now = new Date();
    const today = formatLocalDate(now);
    const todayDate = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const streakStartDate = getHabitStartDate(habit);
    const planEndDate = getHabitEndDate(habit);

    const yesterdayDate = new Date(now);
    yesterdayDate.setDate(yesterdayDate.getDate() - 1);
    const yesterday = formatLocalDate(yesterdayDate);

    const requestedDateRaw = String(req.body?.date || "").trim();
    if (requestedDateRaw) {
      const requestedDate = parseYmdToDate(requestedDateRaw);
      if (!requestedDate) {
        return res.status(400).json({ error: "date must be in YYYY-MM-DD format" });
      }
      if (formatLocalDate(requestedDate) !== today) {
        return res.status(400).json({
          error: "Missed day cannot be marked later. Only today can be marked.",
          code: "BACKFILL_NOT_ALLOWED",
          today,
        });
      }
    }

    if (logs.includes(today)) {
      return res.json({
        message: "Already marked for today",
        habit: {
          ...habit,
          logs,
          currentStreak,
          longestStreak,
        },
      });
    }

    if (todayDate < streakStartDate) {
      return res.status(400).json({
        error: "This streak has not started yet",
        code: "STREAK_NOT_STARTED",
        startDate: formatLocalDate(streakStartDate),
      });
    }

    if (planEndDate && todayDate > planEndDate) {
      return res.status(400).json({
        error: "This streak plan has already ended",
        code: "PLAN_ENDED",
        planEndDate: formatLocalDate(planEndDate),
      });
    }

    if (logs.includes(yesterday)) {
      currentStreak += 1;
    } else {
      currentStreak = 1;
    }

    if (currentStreak > longestStreak) {
      longestStreak = currentStreak;
    }

    logs.push(today);

    await db.execute({
      sql: `
        UPDATE habits
        SET logs = ?, currentStreak = ?, longestStreak = ?
        WHERE id = ? AND userId = ?
      `,
      args: [JSON.stringify(logs), currentStreak, longestStreak, habitId, req.auth.user.id],
    });

    return res.json({
      message: "Marked successfully",
      habit: {
        ...habit,
        logs,
        currentStreak,
        longestStreak,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch("/api/habits/:id/archive", requireAuth, async (req, res) => {
  try {
    const habitId = Number(req.params.id);
    if (!Number.isInteger(habitId) || habitId <= 0) {
      return res.status(400).json({ error: "Invalid habit id" });
    }

    const result = await db.execute({
      sql: `
        UPDATE habits
        SET archived = 1, archivedAt = COALESCE(archivedAt, CURRENT_TIMESTAMP)
        WHERE id = ? AND userId = ?
        RETURNING *
      `,
      args: [habitId, req.auth.user.id],
    });

    if (!result.rows.length) {
      return res.status(404).json({ error: "Habit not found" });
    }

    return res.json({
      message: "Streak archived.",
      habit: normalizeHabit(result.rows[0]),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.patch("/api/habits/:id/unarchive", requireAuth, async (req, res) => {
  try {
    const habitId = Number(req.params.id);
    if (!Number.isInteger(habitId) || habitId <= 0) {
      return res.status(400).json({ error: "Invalid habit id" });
    }

    const result = await db.execute({
      sql: `
        UPDATE habits
        SET archived = 0, archivedAt = NULL
        WHERE id = ? AND userId = ?
        RETURNING *
      `,
      args: [habitId, req.auth.user.id],
    });

    if (!result.rows.length) {
      return res.status(404).json({ error: "Habit not found" });
    }

    return res.json({
      message: "Streak moved back to active list.",
      habit: normalizeHabit(result.rows[0]),
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete("/api/habits/:id", requireAuth, async (req, res) => {
  try {
    const habitId = Number(req.params.id);
    if (!Number.isInteger(habitId) || habitId <= 0) {
      return res.status(400).json({ error: "Invalid habit id" });
    }

    const result = await db.execute({
      sql: "DELETE FROM habits WHERE id = ? AND userId = ? RETURNING id",
      args: [habitId, req.auth.user.id],
    });

    if (!result.rows.length) {
      return res.status(404).json({ error: "Habit not found" });
    }

    return res.json({ message: "Streak deleted.", id: habitId });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "streak-backend" });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
