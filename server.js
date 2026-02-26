const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const dns = require("node:dns");
const nodemailer = require("nodemailer");
const path = require("path");
const { createClient } = require("@libsql/client");
require("dotenv").config();

try {
  dns.setDefaultResultOrder("ipv4first");
} catch {
  // Ignore on older Node runtimes where this API may not exist.
}

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
const EMAIL_VERIFICATION_REQUIRED = true;
const RESET_PASSWORD_TOKEN_TTL_MINUTES = Number(
  process.env.RESET_PASSWORD_TOKEN_TTL_MINUTES || 30
);
const HABIT_NAME_MAX_LENGTH = Number(process.env.HABIT_NAME_MAX_LENGTH || 48);
const REMINDER_ENGINE_ENABLED = String(
  process.env.REMINDER_ENGINE_ENABLED || "1"
).trim() !== "0";
const REMINDER_TICK_SECONDS = Math.max(
  15,
  Number(process.env.REMINDER_TICK_SECONDS || 60)
);
const REMINDER_LOG_RETENTION_DAYS = Math.max(
  7,
  Number(process.env.REMINDER_LOG_RETENTION_DAYS || 90)
);
const REMINDER_DEFAULTS = Object.freeze({
  followUpEnabled: true,
  followUpDelayMinutes: 75,
  lastChanceEnabled: true,
  lastChanceTime: "22:30",
  riskAlertEnabled: true,
  riskThresholdDays: 5,
  riskLeadMinutes: 45,
  weeklyPlanningEnabled: true,
  weeklyPlanningTime: "18:00",
  quietHoursEnabled: false,
  quietHoursStart: "23:00",
  quietHoursEnd: "07:00",
  snoozeMinutes: 30,
  snoozeUntil: null,
});

const GMAIL_USER = process.env.GMAIL_USER || "";
const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD || "";
const MAIL_FROM = process.env.MAIL_FROM || GMAIL_USER;
const SMTP_HOST = String(process.env.SMTP_HOST || "smtp.gmail.com").trim();
const SMTP_PORT = Number(process.env.SMTP_PORT || 465);
const SMTP_SECURE = String(process.env.SMTP_SECURE || "1").trim() !== "0";
const SMTP_FAMILY = Number(process.env.SMTP_FAMILY || 4) === 6 ? 6 : 4;
const EMAIL_PROVIDER = String(process.env.EMAIL_PROVIDER || "auto")
  .trim()
  .toLowerCase();
const RESEND_API_KEY = String(process.env.RESEND_API_KEY || "").trim();
const RESEND_API_URL = String(
  process.env.RESEND_API_URL || "https://api.resend.com/emails"
).trim();
const RESEND_FROM = String(process.env.RESEND_FROM || "onboarding@resend.dev").trim();
const DEFAULT_GOOGLE_SCRIPT_WEBHOOK_URL =
  "https://script.google.com/macros/s/AKfycbzMKm4wdFlshWl7UfRrjqj5Q3ex7I2YsvhZa9k2vGherhGZc0lrDbhLFrG6R2thWq_98w/exec";
const GOOGLE_SCRIPT_WEBHOOK_URL = String(
  process.env.GOOGLE_SCRIPT_WEBHOOK_URL || DEFAULT_GOOGLE_SCRIPT_WEBHOOK_URL
).trim();
const FRONTEND_APP_URL = String(process.env.FRONTEND_APP_URL || "").trim();
const FRONTEND_RESET_URL =
  process.env.FRONTEND_RESET_URL ||
  "http://127.0.0.1:5500/streak-frontend/reset-password.html";

let mailTransporter = null;
let reminderTicker = null;
let reminderTickRunning = false;
let reminderLastRunAt = null;
let reminderLastError = "";
let reminderSentCount = 0;
let reminderFailedCount = 0;
let reminderLastCleanupAt = 0;

function isSmtpConnectivityError(error) {
  const code = String(error?.code || "").trim().toUpperCase();
  return (
    code === "ENETUNREACH" ||
    code === "EHOSTUNREACH" ||
    code === "ETIMEDOUT" ||
    code === "ECONNREFUSED" ||
    code === "ECONNRESET" ||
    code === "EAI_AGAIN" ||
    code === "ESOCKET"
  );
}

function isGmailAddress(email) {
  return /^[^\s@]+@gmail\.com$/i.test(String(email || "").trim());
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function toSafeMultilineHtml(value) {
  return escapeHtml(value).replace(/\r?\n/g, "<br />");
}

function buildBrandedEmailHtml({
  preheader = "",
  title = "",
  subtitle = "",
  name = "",
  contentHtml = "",
  footer = "You are receiving this email from Streak Up.",
}) {
  const safePreheader = escapeHtml(preheader);
  const safeTitle = escapeHtml(title);
  const safeSubtitle = escapeHtml(subtitle);
  const safeName = escapeHtml(name || "there");
  const safeFooter = escapeHtml(footer);

  return `
    <!doctype html>
    <html lang="en">
      <head>
        <meta charset="UTF-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>${safeTitle}</title>
      </head>
      <body style="margin:0;padding:0;background:#eef7f5;">
        <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">${safePreheader}</div>
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#eef7f5;padding:24px 12px;">
          <tr>
            <td align="center">
              <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:620px;">
                <tr>
                  <td style="border:1px solid #d5e7e0;border-bottom:none;border-radius:18px 18px 0 0;background:#ffffff;padding:16px 22px;">
                    <table role="presentation" width="100%" cellspacing="0" cellpadding="0">
                      <tr>
                        <td width="36" style="vertical-align:middle;">
                          <span style="display:inline-block;width:32px;height:32px;border-radius:8px;background:#0f8a73;color:#ffffff;font-size:13px;line-height:32px;text-align:center;font-weight:800;font-family:Arial,sans-serif;">SU</span>
                        </td>
                        <td style="padding-left:10px;vertical-align:middle;">
                          <p style="margin:0;font-size:27px;line-height:1.05;font-family:Georgia,'Times New Roman',serif;color:#16312e;font-weight:700;">Streak Up</p>
                        </td>
                      </tr>
                    </table>
                  </td>
                </tr>
                <tr>
                  <td style="background:#0f8a73;padding:28px 24px;color:#ffffff;text-align:center;">
                    <p style="margin:0 0 8px 0;font-size:11px;letter-spacing:2px;font-weight:700;text-transform:uppercase;opacity:0.92;font-family:Arial,sans-serif;">Account Security</p>
                    <h1 style="margin:0;font-size:34px;line-height:1.2;font-weight:800;font-family:Arial,sans-serif;">${safeTitle}</h1>
                    <p style="margin:10px 0 0 0;font-size:15px;line-height:1.55;opacity:0.95;font-family:Arial,sans-serif;">${safeSubtitle}</p>
                  </td>
                </tr>
                <tr>
                  <td style="border:1px solid #d5e7e0;border-top:none;border-radius:0 0 18px 18px;background:#ffffff;padding:24px 22px;">
                    <p style="margin:0 0 12px 0;font-size:16px;line-height:1.55;color:#16312e;font-family:Arial,sans-serif;">Hi ${safeName},</p>
                    ${contentHtml}
                    <div style="margin:18px 0 0 0;padding:10px 12px;border-radius:10px;background:#f4fbf8;border:1px solid #d5ebe2;">
                      <p style="margin:0;font-size:12px;line-height:1.6;color:#587773;font-family:Arial,sans-serif;">${safeFooter}</p>
                    </div>
                  </td>
                </tr>
                <tr>
                  <td style="padding:12px 6px 0 6px;text-align:center;">
                    <p style="margin:0;font-size:11px;line-height:1.5;color:#7f9491;font-family:Arial,sans-serif;">Built with consistency, one day at a time.</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
        </table>
      </body>
    </html>
  `;
}

function buildOtpDigitsHtml(otpValue) {
  const digits = String(otpValue || "").trim().split("");
  if (!digits.length) {
    return `<p style="margin:14px 0 10px 0;font-size:28px;line-height:1;font-weight:800;color:#0f8a73;font-family:Arial,sans-serif;">${escapeHtml(otpValue)}</p>`;
  }

  const cells = digits
    .map(
      (digit) => `
        <td style="padding:0;">
          <div style="width:48px;padding:11px 0;border:1px solid #b9d8ce;border-radius:10px;background:#f5fbf8;text-align:center;font-size:28px;line-height:1;font-weight:800;color:#0f8a73;font-family:Arial,sans-serif;">
            ${escapeHtml(digit)}
          </div>
        </td>
      `
    )
    .join("");

  return `
    <table role="presentation" cellspacing="0" cellpadding="0" style="margin:14px 0 10px 0;border-collapse:separate;border-spacing:8px 0;">
      <tr>
        ${cells}
      </tr>
    </table>
  `;
}

function getMailTransporter() {
  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    throw new Error("Email service is not configured. Set GMAIL_USER and GMAIL_APP_PASSWORD in .env");
  }

  if (!mailTransporter) {
    mailTransporter = nodemailer.createTransport({
      host: SMTP_HOST,
      port: SMTP_PORT,
      secure: SMTP_SECURE,
      family: SMTP_FAMILY,
      connectionTimeout: 15000,
      greetingTimeout: 10000,
      socketTimeout: 20000,
      tls: {
        servername: SMTP_HOST,
      },
      auth: {
        user: GMAIL_USER,
        pass: GMAIL_APP_PASSWORD,
      },
    });
  }

  return mailTransporter;
}

function getResolvedEmailProvider() {
  if (
    EMAIL_PROVIDER === "google_script" ||
    EMAIL_PROVIDER === "google_webhook" ||
    EMAIL_PROVIDER === "apps_script" ||
    EMAIL_PROVIDER === "google_apps_script"
  ) {
    return "google_script";
  }
  if (EMAIL_PROVIDER === "smtp" || EMAIL_PROVIDER === "resend") {
    return EMAIL_PROVIDER;
  }
  return "auto";
}

function getResendFromAddress() {
  const from = String(RESEND_FROM || "onboarding@resend.dev").trim();
  return from || "onboarding@resend.dev";
}

function buildResendMessage(message = {}) {
  const safeMessage = message && typeof message === "object" ? message : {};
  return {
    ...safeMessage,
    from: getResendFromAddress(),
  };
}

function htmlToPlainText(value) {
  return String(value || "")
    .replace(/<\s*br\s*\/?>/gi, "\n")
    .replace(/<\/\s*p\s*>/gi, "\n\n")
    .replace(/<[^>]*>/g, "")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, "\"")
    .replace(/&#39;/gi, "'")
    .trim();
}

async function sendViaGoogleScript({ to, subject, text, html }) {
  if (!GOOGLE_SCRIPT_WEBHOOK_URL) {
    throw new Error(
      "Google Apps Script webhook is not configured. Set GOOGLE_SCRIPT_WEBHOOK_URL in environment variables."
    );
  }
  if (typeof fetch !== "function") {
    throw new Error("Global fetch is not available in this Node runtime for webhook email delivery.");
  }

  const toList = Array.isArray(to)
    ? to.map((entry) => String(entry || "").trim()).filter((entry) => Boolean(entry))
    : [String(to || "").trim()].filter((entry) => Boolean(entry));
  if (!toList.length) {
    throw new Error("Webhook payload requires at least one recipient.");
  }

  const bodyText = String(text || "").trim() || htmlToPlainText(html) || " ";
  const response = await fetch(GOOGLE_SCRIPT_WEBHOOK_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      to: toList.join(","),
      subject: String(subject || "").trim() || "Streak Up Notification",
      body: bodyText,
      textBody: bodyText,
      htmlBody: String(html || "").trim(),
      html: String(html || "").trim(),
    }),
  });

  let responseText = "";
  try {
    responseText = await response.text();
  } catch {
    responseText = "";
  }

  if (!response.ok) {
    const shortResponse = String(responseText || "").trim().slice(0, 220);
    throw new Error(
      `Google Apps Script webhook request failed (${response.status}).${shortResponse ? ` ${shortResponse}` : ""}`
    );
  }

  let parsedResponse = null;
  if (responseText) {
    try {
      parsedResponse = JSON.parse(responseText);
    } catch {
      parsedResponse = null;
    }
  }

  if (parsedResponse && parsedResponse.success === false) {
    const errorMessage = String(parsedResponse.error || "unknown webhook error").trim();
    throw new Error(`Google Apps Script webhook error: ${errorMessage || "unknown webhook error"}`);
  }
}

async function sendViaResend({ to, subject, text, html, from }) {
  if (!RESEND_API_KEY) {
    throw new Error(
      "Resend is not configured. Set RESEND_API_KEY (and optional RESEND_FROM) in environment variables."
    );
  }
  if (typeof fetch !== "function") {
    throw new Error("Global fetch is not available in this Node runtime for Resend API.");
  }

  const toList = Array.isArray(to)
    ? to.map((entry) => String(entry || "").trim()).filter((entry) => Boolean(entry))
    : [String(to || "").trim()].filter((entry) => Boolean(entry));
  if (!toList.length) {
    throw new Error("Resend payload requires at least one recipient.");
  }

  const response = await fetch(RESEND_API_URL, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${RESEND_API_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from: String(from || getResendFromAddress()).trim(),
      to: toList,
      subject: String(subject || "").trim(),
      text: String(text || ""),
      html: String(html || ""),
    }),
  });

  if (!response.ok) {
    let responseText = "";
    try {
      responseText = await response.text();
    } catch {
      responseText = "";
    }
    const trimmedResponseText = String(responseText || "").trim();
    const shortResponse = trimmedResponseText.slice(0, 220);
    throw new Error(
      `Resend API request failed (${response.status}).${shortResponse ? ` ${shortResponse}` : ""}`
    );
  }
}

async function sendEmailMessage(message) {
  const provider = getResolvedEmailProvider();

  if (provider === "resend") {
    if (GOOGLE_SCRIPT_WEBHOOK_URL) {
      console.warn(
        "EMAIL_PROVIDER=resend ignored because GOOGLE_SCRIPT_WEBHOOK_URL is configured; using Google Apps Script webhook."
      );
      await sendViaGoogleScript(message);
      return;
    }
    await sendViaResend(buildResendMessage(message));
    return;
  }

  if (provider === "google_script") {
    await sendViaGoogleScript(message);
    return;
  }

  if (provider === "smtp") {
    const transporter = getMailTransporter();
    await transporter.sendMail(message);
    return;
  }

  // Auto mode: prefer webhook delivery on free hosts where SMTP/Resend may be restricted.
  if (GOOGLE_SCRIPT_WEBHOOK_URL) {
    await sendViaGoogleScript(message);
    return;
  }

  try {
    const transporter = getMailTransporter();
    await transporter.sendMail(message);
  } catch (smtpError) {
    if (isSmtpConnectivityError(smtpError)) {
      if (GOOGLE_SCRIPT_WEBHOOK_URL) {
        console.warn("SMTP connectivity failed; falling back to Google Apps Script webhook.");
        await sendViaGoogleScript(message);
        return;
      }
      if (RESEND_API_KEY) {
        console.warn("SMTP connectivity failed; falling back to Resend API.");
        await sendViaResend(buildResendMessage(message));
        return;
      }
      throw new Error(
        "SMTP connection failed. On Render free plan SMTP ports are blocked. Set GOOGLE_SCRIPT_WEBHOOK_URL or RESEND_API_KEY for API-based email delivery."
      );
    }
    throw smtpError;
  }
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
  const safeMinutes = escapeHtml(EMAIL_OTP_TTL_MINUTES);
  const otpDigitsHtml = buildOtpDigitsHtml(otp);
  const textName = String(name || "there").trim() || "there";
  const plainTextOtpMessage = [
    `Hi ${textName},`,
    "",
    "Welcome to Streak Up.",
    "Use this one-time code to verify your account:",
    "",
    `      ${otp}`,
    "",
    `This OTP expires in ${EMAIL_OTP_TTL_MINUTES} minutes.`,
    "",
    "Security tips:",
    "- Never share this OTP with anyone.",
    "- Streak Up team will never ask for this code.",
    "",
    "If you did not create this account, you can safely ignore this email.",
    "",
    "Streak Up Team",
  ].join("\n");
  const html = buildBrandedEmailHtml({
    preheader: "Verify your Streak Up account with OTP",
    title: "Email Verification OTP",
    subtitle: "Confirm your account and start building your streak momentum.",
    name,
    contentHtml: `
      <p style="margin:0;font-size:14px;line-height:1.6;color:#35514d;">
        Use this one-time code to verify your Streak Up account:
      </p>
      ${otpDigitsHtml}
      <p style="margin:0;font-size:13px;line-height:1.5;color:#5f7673;">
        This OTP expires in ${safeMinutes} minutes.
      </p>
      <div style="margin:12px 0 0 0;padding:10px 12px;border-radius:10px;background:#fff8ef;border:1px solid #f2dbc1;">
        <p style="margin:0;font-size:12px;line-height:1.6;color:#7c5a32;">
          Security note: Never share this code with anyone. Streak Up team will never ask for your OTP.
        </p>
      </div>
    `,
    footer: "If you did not create this account, you can ignore this email.",
  });

  try {
    await sendEmailMessage({
      from: MAIL_FROM,
      to: email,
      subject: "Verify your Streak Up account",
      text: plainTextOtpMessage,
      html,
    });
  } catch (error) {
    console.error("Failed to send verification OTP:", error);
    if (isSmtpConnectivityError(error)) {
      throw new Error("OTP email service is temporarily unavailable. Please try again in 1-2 minutes.");
    }
    throw error;
  }
}

async function sendPasswordResetOtp({ email, name, otp }) {
  const safeMinutes = escapeHtml(EMAIL_OTP_TTL_MINUTES);
  const otpDigitsHtml = buildOtpDigitsHtml(otp);
  const textName = String(name || "there").trim() || "there";
  const plainTextResetOtpMessage = [
    `Hi ${textName},`,
    "",
    "Use this OTP to reset your Streak Up password:",
    "",
    `      ${otp}`,
    "",
    `This OTP expires in ${EMAIL_OTP_TTL_MINUTES} minutes.`,
    "",
    "Security tips:",
    "- Never share this OTP with anyone.",
    "- Streak Up team will never ask for this code.",
    "",
    "If you did not request this, you can safely ignore this email.",
    "",
    "Streak Up Team",
  ].join("\n");

  const html = buildBrandedEmailHtml({
    preheader: "Use OTP to reset your Streak Up password",
    title: "Password Reset OTP",
    subtitle: "Enter this OTP on the reset password screen.",
    name,
    contentHtml: `
      <p style="margin:0;font-size:14px;line-height:1.6;color:#35514d;">
        Use this OTP to reset your Streak Up password:
      </p>
      ${otpDigitsHtml}
      <p style="margin:0;font-size:13px;line-height:1.5;color:#5f7673;">
        This OTP expires in ${safeMinutes} minutes.
      </p>
      <div style="margin:12px 0 0 0;padding:10px 12px;border-radius:10px;background:#fff8ef;border:1px solid #f2dbc1;">
        <p style="margin:0;font-size:12px;line-height:1.6;color:#7c5a32;">
          Security note: Never share this code with anyone. Streak Up team will never ask for your OTP.
        </p>
      </div>
    `,
    footer: "If you did not request password reset, you can ignore this email.",
  });

  try {
    await sendEmailMessage({
      from: MAIL_FROM,
      to: email,
      subject: "Your Streak Up password reset OTP",
      text: plainTextResetOtpMessage,
      html,
    });
  } catch (error) {
    console.error("Failed to send password reset OTP:", error);
    if (isSmtpConnectivityError(error)) {
      throw new Error("Password reset OTP service is temporarily unavailable. Please try again in 1-2 minutes.");
    }
    throw error;
  }
}

async function sendPasswordResetEmail({ email, name, rawToken }) {
  const resetLink = `${FRONTEND_RESET_URL}?token=${encodeURIComponent(rawToken)}`;
  const safeResetLink = escapeHtml(resetLink);
  const safeMinutes = escapeHtml(RESET_PASSWORD_TOKEN_TTL_MINUTES);
  const html = buildBrandedEmailHtml({
    preheader: "Reset your Streak Up password",
    title: "Password Reset Request",
    subtitle: "Secure your account and continue your streaks.",
    name,
    contentHtml: `
      <p style="margin:0;font-size:14px;line-height:1.6;color:#35514d;">
        We received a request to reset your password.
      </p>
      <div style="margin:16px 0 12px 0;">
        <a href="${safeResetLink}" style="display:inline-block;padding:11px 18px;border-radius:11px;background:linear-gradient(135deg,#0f9d7d 0%,#2089d5 100%);color:#ffffff;text-decoration:none;font-size:14px;font-weight:700;">
          Reset Password
        </a>
      </div>
      <p style="margin:0;font-size:13px;line-height:1.5;color:#5f7673;">
        This link expires in ${safeMinutes} minutes.
      </p>
      <div style="margin:12px 0 0 0;padding:10px 12px;border-radius:10px;background:#f6f9fb;border:1px solid #dde7ea;">
        <p style="margin:0 0 4px 0;font-size:12px;color:#667d7a;">If the button does not work, copy this URL:</p>
        <p style="margin:0;font-size:12px;line-height:1.45;color:#35514d;word-break:break-all;">${safeResetLink}</p>
      </div>
    `,
    footer: "If you did not request this, ignore this email and your password will remain unchanged.",
  });

  try {
    await sendEmailMessage({
      from: MAIL_FROM,
      to: email,
      subject: "Reset your Streak Up password",
      text: `Hi ${name},\nReset your password using this link:\n${resetLink}\nThis link expires in ${RESET_PASSWORD_TOKEN_TTL_MINUTES} minutes.`,
      html,
    });
  } catch (error) {
    console.error("Failed to send password reset email:", error);
    if (isSmtpConnectivityError(error)) {
      throw new Error("Password reset email service is temporarily unavailable. Please try again in 1-2 minutes.");
    }
    throw error;
  }
}

async function sendReminderEmail({
  email,
  name,
  subject,
  title,
  body,
  meta = "",
}) {
  const textName = String(name || "User");
  const safeName = escapeHtml(name);
  const safeTitle = escapeHtml(title);
  const safeBody = toSafeMultilineHtml(body);
  const safeMeta = toSafeMultilineHtml(meta);
  const appLink = FRONTEND_APP_URL ? escapeHtml(FRONTEND_APP_URL) : "";
  const html = buildBrandedEmailHtml({
    preheader: `${title} - Streak Up`,
    title,
    subtitle: "Stay consistent and protect your streak momentum.",
    name,
    contentHtml: `
      <p style="margin:0 0 10px 0;font-size:15px;line-height:1.6;color:#24423f;font-weight:700;">${safeTitle}</p>
      <p style="margin:0;font-size:14px;line-height:1.65;color:#35514d;">${safeBody}</p>
      ${safeMeta ? `<p style="margin:10px 0 0 0;font-size:13px;line-height:1.55;color:#5f7673;">${safeMeta}</p>` : ""}
      ${appLink ? `
        <div style="margin:14px 0 0 0;">
          <a href="${appLink}" style="display:inline-block;padding:10px 16px;border-radius:10px;background:#f3fbf8;border:1px solid #b8ddd1;color:#0f8a73;text-decoration:none;font-size:13px;font-weight:700;">
            Open Streak Up
          </a>
        </div>
      ` : ""}
    `,
    footer: "This reminder was sent by your configured reminder settings.",
  });

  await sendEmailMessage({
    from: MAIL_FROM,
    to: email,
    subject,
    text: `Hi ${textName},\n${title}\n${body}${meta ? `\n${meta}` : ""}${FRONTEND_APP_URL ? `\n${FRONTEND_APP_URL}` : ""}`,
    html,
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

function clampInteger(value, min, max, fallback) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  const rounded = Math.round(parsed);
  if (rounded < min || rounded > max) {
    return fallback;
  }
  return rounded;
}

function parseTimeParts(value) {
  const raw = String(value || "").trim();
  const match = /^([01]\d|2[0-3]):([0-5]\d)$/.exec(raw);
  if (!match) {
    return null;
  }
  return {
    hour: Number(match[1]),
    minute: Number(match[2]),
  };
}

function getDateMinutes(date) {
  return date.getHours() * 60 + date.getMinutes();
}

function buildDateAtTime(date, timeValue) {
  const parts = parseTimeParts(timeValue);
  if (!parts) {
    return null;
  }
  return new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
    parts.hour,
    parts.minute,
    0,
    0
  );
}

function isAlwaysQuietHours(settings) {
  const start = parseTimeParts(settings?.quietHoursStart);
  const end = parseTimeParts(settings?.quietHoursEnd);
  if (!start || !end) {
    return false;
  }
  return start.hour === end.hour && start.minute === end.minute;
}

function isInsideQuietHours(date, settings) {
  if (!settings?.quietHoursEnabled) {
    return false;
  }
  const start = parseTimeParts(settings.quietHoursStart);
  const end = parseTimeParts(settings.quietHoursEnd);
  if (!start || !end) {
    return false;
  }
  if (start.hour === end.hour && start.minute === end.minute) {
    return true;
  }

  const current = getDateMinutes(date);
  const startMinutes = start.hour * 60 + start.minute;
  const endMinutes = end.hour * 60 + end.minute;
  if (startMinutes < endMinutes) {
    return current >= startMinutes && current < endMinutes;
  }
  return current >= startMinutes || current < endMinutes;
}

function normalizeSnoozeUntil(value) {
  const raw = String(value || "").trim();
  if (!raw) {
    return null;
  }
  const parsed = new Date(raw);
  if (Number.isNaN(parsed.getTime())) {
    return null;
  }
  return parsed.toISOString();
}

function sanitizeReminderSettings(input = {}, base = REMINDER_DEFAULTS) {
  const source =
    input && typeof input === "object" ? input : {};
  const fallback =
    base && typeof base === "object" ? base : REMINDER_DEFAULTS;

  const followUpEnabled =
    source.followUpEnabled !== undefined
      ? Boolean(source.followUpEnabled)
      : Boolean(fallback.followUpEnabled);
  const followUpDelayMinutes = clampInteger(
    source.followUpDelayMinutes,
    5,
    360,
    clampInteger(
      fallback.followUpDelayMinutes,
      5,
      360,
      REMINDER_DEFAULTS.followUpDelayMinutes
    )
  );

  const lastChanceEnabled =
    source.lastChanceEnabled !== undefined
      ? Boolean(source.lastChanceEnabled)
      : Boolean(fallback.lastChanceEnabled);
  const lastChanceTime = isValidTimeHHMM(source.lastChanceTime)
    ? String(source.lastChanceTime).trim()
    : (isValidTimeHHMM(fallback.lastChanceTime)
      ? String(fallback.lastChanceTime).trim()
      : REMINDER_DEFAULTS.lastChanceTime);

  const riskAlertEnabled =
    source.riskAlertEnabled !== undefined
      ? Boolean(source.riskAlertEnabled)
      : Boolean(fallback.riskAlertEnabled);
  const riskThresholdDays = clampInteger(
    source.riskThresholdDays,
    1,
    3650,
    clampInteger(
      fallback.riskThresholdDays,
      1,
      3650,
      REMINDER_DEFAULTS.riskThresholdDays
    )
  );
  const riskLeadMinutes = clampInteger(
    source.riskLeadMinutes,
    5,
    360,
    clampInteger(
      fallback.riskLeadMinutes,
      5,
      360,
      REMINDER_DEFAULTS.riskLeadMinutes
    )
  );

  const weeklyPlanningEnabled =
    source.weeklyPlanningEnabled !== undefined
      ? Boolean(source.weeklyPlanningEnabled)
      : Boolean(fallback.weeklyPlanningEnabled);
  const weeklyPlanningTime = isValidTimeHHMM(source.weeklyPlanningTime)
    ? String(source.weeklyPlanningTime).trim()
    : (isValidTimeHHMM(fallback.weeklyPlanningTime)
      ? String(fallback.weeklyPlanningTime).trim()
      : REMINDER_DEFAULTS.weeklyPlanningTime);

  const quietHoursEnabled =
    source.quietHoursEnabled !== undefined
      ? Boolean(source.quietHoursEnabled)
      : Boolean(fallback.quietHoursEnabled);
  const quietHoursStart = isValidTimeHHMM(source.quietHoursStart)
    ? String(source.quietHoursStart).trim()
    : (isValidTimeHHMM(fallback.quietHoursStart)
      ? String(fallback.quietHoursStart).trim()
      : REMINDER_DEFAULTS.quietHoursStart);
  const quietHoursEnd = isValidTimeHHMM(source.quietHoursEnd)
    ? String(source.quietHoursEnd).trim()
    : (isValidTimeHHMM(fallback.quietHoursEnd)
      ? String(fallback.quietHoursEnd).trim()
      : REMINDER_DEFAULTS.quietHoursEnd);

  const snoozeMinutes = clampInteger(
    source.snoozeMinutes,
    5,
    720,
    clampInteger(
      fallback.snoozeMinutes,
      5,
      720,
      REMINDER_DEFAULTS.snoozeMinutes
    )
  );

  const snoozeUntil =
    source.snoozeUntil !== undefined
      ? normalizeSnoozeUntil(source.snoozeUntil)
      : normalizeSnoozeUntil(fallback.snoozeUntil);

  return {
    followUpEnabled,
    followUpDelayMinutes,
    lastChanceEnabled,
    lastChanceTime,
    riskAlertEnabled,
    riskThresholdDays,
    riskLeadMinutes,
    weeklyPlanningEnabled,
    weeklyPlanningTime,
    quietHoursEnabled,
    quietHoursStart,
    quietHoursEnd,
    snoozeMinutes,
    snoozeUntil,
  };
}

function normalizeReminderSettingsRow(row) {
  const base = {
    followUpEnabled: Number(row?.followUpEnabled || 0) === 1,
    followUpDelayMinutes: Number(row?.followUpDelayMinutes || 0),
    lastChanceEnabled: Number(row?.lastChanceEnabled || 0) === 1,
    lastChanceTime: String(row?.lastChanceTime || "").trim(),
    riskAlertEnabled: Number(row?.riskAlertEnabled || 0) === 1,
    riskThresholdDays: Number(row?.riskThresholdDays || 0),
    riskLeadMinutes: Number(row?.riskLeadMinutes || 0),
    weeklyPlanningEnabled: Number(row?.weeklyPlanningEnabled || 0) === 1,
    weeklyPlanningTime: String(row?.weeklyPlanningTime || "").trim(),
    quietHoursEnabled: Number(row?.quietHoursEnabled || 0) === 1,
    quietHoursStart: String(row?.quietHoursStart || "").trim(),
    quietHoursEnd: String(row?.quietHoursEnd || "").trim(),
    snoozeMinutes: Number(row?.snoozeMinutes || 0),
    snoozeUntil: row?.snoozeUntil || null,
  };
  return sanitizeReminderSettings(base, REMINDER_DEFAULTS);
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

function getNormalizedHabitLogs(habit) {
  return Array.from(
    new Set(
      (Array.isArray(habit?.logs) ? habit.logs : [])
        .map((day) => normalizeYmdInput(day))
        .filter((day) => Boolean(parseYmdToDate(day)))
    )
  ).sort();
}

function getHabitDoneDaysInPlan(habit) {
  const logs = getNormalizedHabitLogs(habit);
  const startStr = formatLocalDate(getHabitStartDate(habit));
  const endDate = getHabitEndDate(habit);
  const endStr = endDate ? formatLocalDate(endDate) : "";
  return logs.filter((day) => day >= startStr && (!endStr || day <= endStr)).length;
}

function isHabitCompleted(habit) {
  const targetDays = Number(habit?.targetDays || 0);
  if (!Number.isInteger(targetDays) || targetDays <= 0) {
    return false;
  }
  return getHabitDoneDaysInPlan(habit) >= targetDays;
}

function isHabitDateInPlan(habit, dayStr) {
  const startDate = formatLocalDate(getHabitStartDate(habit));
  const endDate = getHabitEndDate(habit);
  const endDateStr = endDate ? formatLocalDate(endDate) : "";
  if (dayStr < startDate) {
    return false;
  }
  if (endDateStr && dayStr > endDateStr) {
    return false;
  }
  return true;
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

  if (EMAIL_VERIFICATION_REQUIRED && Number(row.isVerified || 0) !== 1) {
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

async function ensureReminderSchema() {
  await db.execute(`
    CREATE TABLE IF NOT EXISTS reminder_settings (
      userId INTEGER PRIMARY KEY,
      followUpEnabled INTEGER NOT NULL DEFAULT 1,
      followUpDelayMinutes INTEGER NOT NULL DEFAULT 75,
      lastChanceEnabled INTEGER NOT NULL DEFAULT 1,
      lastChanceTime TEXT NOT NULL DEFAULT '22:30',
      riskAlertEnabled INTEGER NOT NULL DEFAULT 1,
      riskThresholdDays INTEGER NOT NULL DEFAULT 5,
      riskLeadMinutes INTEGER NOT NULL DEFAULT 45,
      weeklyPlanningEnabled INTEGER NOT NULL DEFAULT 1,
      weeklyPlanningTime TEXT NOT NULL DEFAULT '18:00',
      quietHoursEnabled INTEGER NOT NULL DEFAULT 0,
      quietHoursStart TEXT NOT NULL DEFAULT '23:00',
      quietHoursEnd TEXT NOT NULL DEFAULT '07:00',
      snoozeMinutes INTEGER NOT NULL DEFAULT 30,
      snoozeUntil TEXT,
      createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  const settingsInfo = await db.execute("PRAGMA table_info(reminder_settings)");
  const settingsColumns = new Set(settingsInfo.rows.map((column) => column.name));

  if (!settingsColumns.has("followUpEnabled")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN followUpEnabled INTEGER NOT NULL DEFAULT 1");
  }
  if (!settingsColumns.has("followUpDelayMinutes")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN followUpDelayMinutes INTEGER NOT NULL DEFAULT 75");
  }
  if (!settingsColumns.has("lastChanceEnabled")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN lastChanceEnabled INTEGER NOT NULL DEFAULT 1");
  }
  if (!settingsColumns.has("lastChanceTime")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN lastChanceTime TEXT NOT NULL DEFAULT '22:30'");
  }
  if (!settingsColumns.has("riskAlertEnabled")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN riskAlertEnabled INTEGER NOT NULL DEFAULT 1");
  }
  if (!settingsColumns.has("riskThresholdDays")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN riskThresholdDays INTEGER NOT NULL DEFAULT 5");
  }
  if (!settingsColumns.has("riskLeadMinutes")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN riskLeadMinutes INTEGER NOT NULL DEFAULT 45");
  }
  if (!settingsColumns.has("weeklyPlanningEnabled")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN weeklyPlanningEnabled INTEGER NOT NULL DEFAULT 1");
  }
  if (!settingsColumns.has("weeklyPlanningTime")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN weeklyPlanningTime TEXT NOT NULL DEFAULT '18:00'");
  }
  if (!settingsColumns.has("quietHoursEnabled")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN quietHoursEnabled INTEGER NOT NULL DEFAULT 0");
  }
  if (!settingsColumns.has("quietHoursStart")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN quietHoursStart TEXT NOT NULL DEFAULT '23:00'");
  }
  if (!settingsColumns.has("quietHoursEnd")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN quietHoursEnd TEXT NOT NULL DEFAULT '07:00'");
  }
  if (!settingsColumns.has("snoozeMinutes")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN snoozeMinutes INTEGER NOT NULL DEFAULT 30");
  }
  if (!settingsColumns.has("snoozeUntil")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN snoozeUntil TEXT");
  }
  if (!settingsColumns.has("createdAt")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");
  }
  if (!settingsColumns.has("updatedAt")) {
    await db.execute("ALTER TABLE reminder_settings ADD COLUMN updatedAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP");
  }

  await db.execute(`
    CREATE TABLE IF NOT EXISTS reminder_delivery_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      eventKey TEXT NOT NULL UNIQUE,
      userId INTEGER NOT NULL,
      habitId INTEGER,
      eventType TEXT NOT NULL,
      eventDate TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'processing',
      subject TEXT,
      body TEXT,
      sentAt TEXT,
      error TEXT,
      createdAt TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db.execute(
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_reminder_delivery_event_key ON reminder_delivery_log(eventKey)"
  );
  await db.execute(
    "CREATE INDEX IF NOT EXISTS idx_reminder_delivery_user_date ON reminder_delivery_log(userId, eventDate)"
  );
  await db.execute(
    "CREATE INDEX IF NOT EXISTS idx_reminder_delivery_created_at ON reminder_delivery_log(createdAt)"
  );
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
    await ensureReminderSchema();

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

async function issuePasswordResetOtpForUser({ userId, name, email }) {
  const otpData = createEmailOtp();

  await db.execute({
    sql: `
      UPDATE users
      SET emailOtpHash = ?, emailOtpExpiresAt = ?, resetPasswordTokenHash = NULL, resetPasswordExpiresAt = NULL
      WHERE id = ?
    `,
    args: [otpData.otpHash, otpData.expiresAt, userId],
  });

  await sendPasswordResetOtp({
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
  if (!EMAIL_VERIFICATION_REQUIRED) {
    return { message: "Email verification is currently disabled. Please login directly." };
  }

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

async function getReminderSettingsForUser(userId) {
  const numericUserId = Number(userId);
  if (!Number.isInteger(numericUserId) || numericUserId <= 0) {
    return sanitizeReminderSettings(REMINDER_DEFAULTS);
  }

  const result = await db.execute({
    sql: "SELECT * FROM reminder_settings WHERE userId = ? LIMIT 1",
    args: [numericUserId],
  });

  if (!result.rows.length) {
    return sanitizeReminderSettings(REMINDER_DEFAULTS);
  }

  return normalizeReminderSettingsRow(result.rows[0]);
}

async function getReminderSettingsForUsers(userIds) {
  const uniqueIds = Array.from(
    new Set(
      (Array.isArray(userIds) ? userIds : [])
        .map((value) => Number(value))
        .filter((value) => Number.isInteger(value) && value > 0)
    )
  );

  const settingsByUserId = new Map();
  if (!uniqueIds.length) {
    return settingsByUserId;
  }

  const placeholders = uniqueIds.map(() => "?").join(", ");
  const result = await db.execute({
    sql: `SELECT * FROM reminder_settings WHERE userId IN (${placeholders})`,
    args: uniqueIds,
  });

  result.rows.forEach((row) => {
    settingsByUserId.set(Number(row.userId), normalizeReminderSettingsRow(row));
  });

  uniqueIds.forEach((userId) => {
    if (!settingsByUserId.has(userId)) {
      settingsByUserId.set(userId, sanitizeReminderSettings(REMINDER_DEFAULTS));
    }
  });

  return settingsByUserId;
}

async function saveReminderSettingsForUser(userId, patch = {}, options = {}) {
  const numericUserId = Number(userId);
  if (!Number.isInteger(numericUserId) || numericUserId <= 0) {
    throw new Error("Invalid user id for reminder settings");
  }

  const replaceAll = Boolean(options.replaceAll);
  const current = await getReminderSettingsForUser(numericUserId);
  const base = replaceAll ? sanitizeReminderSettings(REMINDER_DEFAULTS) : current;
  const merged = {
    ...base,
    ...(patch && typeof patch === "object" ? patch : {}),
  };

  if (patch && Object.prototype.hasOwnProperty.call(patch, "snoozeUntil")) {
    merged.snoozeUntil = patch.snoozeUntil;
  }

  const next = sanitizeReminderSettings(merged, base);
  const nowIso = new Date().toISOString();

  await db.execute({
    sql: `
      INSERT INTO reminder_settings (
        userId,
        followUpEnabled,
        followUpDelayMinutes,
        lastChanceEnabled,
        lastChanceTime,
        riskAlertEnabled,
        riskThresholdDays,
        riskLeadMinutes,
        weeklyPlanningEnabled,
        weeklyPlanningTime,
        quietHoursEnabled,
        quietHoursStart,
        quietHoursEnd,
        snoozeMinutes,
        snoozeUntil,
        createdAt,
        updatedAt
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(userId) DO UPDATE SET
        followUpEnabled = excluded.followUpEnabled,
        followUpDelayMinutes = excluded.followUpDelayMinutes,
        lastChanceEnabled = excluded.lastChanceEnabled,
        lastChanceTime = excluded.lastChanceTime,
        riskAlertEnabled = excluded.riskAlertEnabled,
        riskThresholdDays = excluded.riskThresholdDays,
        riskLeadMinutes = excluded.riskLeadMinutes,
        weeklyPlanningEnabled = excluded.weeklyPlanningEnabled,
        weeklyPlanningTime = excluded.weeklyPlanningTime,
        quietHoursEnabled = excluded.quietHoursEnabled,
        quietHoursStart = excluded.quietHoursStart,
        quietHoursEnd = excluded.quietHoursEnd,
        snoozeMinutes = excluded.snoozeMinutes,
        snoozeUntil = excluded.snoozeUntil,
        updatedAt = excluded.updatedAt
    `,
    args: [
      numericUserId,
      next.followUpEnabled ? 1 : 0,
      next.followUpDelayMinutes,
      next.lastChanceEnabled ? 1 : 0,
      next.lastChanceTime,
      next.riskAlertEnabled ? 1 : 0,
      next.riskThresholdDays,
      next.riskLeadMinutes,
      next.weeklyPlanningEnabled ? 1 : 0,
      next.weeklyPlanningTime,
      next.quietHoursEnabled ? 1 : 0,
      next.quietHoursStart,
      next.quietHoursEnd,
      next.snoozeMinutes,
      next.snoozeUntil || null,
      nowIso,
      nowIso,
    ],
  });

  return next;
}

function isSnoozeActive(settings, now = new Date()) {
  const snoozeUntil = normalizeSnoozeUntil(settings?.snoozeUntil || null);
  if (!snoozeUntil) {
    return false;
  }
  return new Date(snoozeUntil).getTime() > now.getTime();
}

function getFollowUpReminderDate(primaryAt, delayMinutes) {
  const followUp = new Date(primaryAt);
  followUp.setMinutes(followUp.getMinutes() + delayMinutes);
  if (formatLocalDate(followUp) !== formatLocalDate(primaryAt)) {
    return new Date(
      primaryAt.getFullYear(),
      primaryAt.getMonth(),
      primaryAt.getDate(),
      23,
      55,
      0,
      0
    );
  }
  return followUp;
}

function getRiskReminderDate(cutoffAt, leadMinutes) {
  const riskAt = new Date(cutoffAt);
  riskAt.setMinutes(riskAt.getMinutes() - leadMinutes);
  if (formatLocalDate(riskAt) !== formatLocalDate(cutoffAt)) {
    return new Date(
      cutoffAt.getFullYear(),
      cutoffAt.getMonth(),
      cutoffAt.getDate(),
      0,
      5,
      0,
      0
    );
  }
  return riskAt;
}

function buildDueHabitReminderEvent(habit, settings, now) {
  if (!habit?.reminderEnabled || !isValidTimeHHMM(habit?.reminderTime)) {
    return null;
  }

  const today = formatLocalDate(now);
  if (!isHabitDateInPlan(habit, today)) {
    return null;
  }
  if (isHabitCompleted(habit)) {
    return null;
  }

  const logs = new Set(getNormalizedHabitLogs(habit));
  if (logs.has(today)) {
    return null;
  }

  const primaryAt = buildDateAtTime(now, habit.reminderTime);
  if (!primaryAt) {
    return null;
  }

  const streakName = String(habit.name || "your streak").trim() || "your streak";
  const events = [
    {
      type: "primary",
      at: primaryAt,
      subject: `Streak Reminder: ${streakName}`,
      title: "Primary Reminder",
      body: `${streakName} is pending for today. Planned reminder time: ${habit.reminderTime}.`,
      meta: "Mark it complete to keep the streak alive.",
    },
  ];

  if (settings.followUpEnabled) {
    events.push({
      type: "followup",
      at: getFollowUpReminderDate(primaryAt, settings.followUpDelayMinutes),
      subject: `Follow-up Nudge: ${streakName}`,
      title: "Follow-up Nudge",
      body: `${streakName} is still pending. Please complete it now.`,
      meta: "This nudge is sent only when today is still unmarked.",
    });
  }

  const cutoffTime = isValidTimeHHMM(settings.lastChanceTime)
    ? settings.lastChanceTime
    : REMINDER_DEFAULTS.lastChanceTime;
  const cutoffAt = buildDateAtTime(now, cutoffTime);

  const currentStreak = Math.max(0, Number(habit.currentStreak || 0));
  if (settings.riskAlertEnabled && cutoffAt && currentStreak >= settings.riskThresholdDays) {
    events.push({
      type: "risk",
      at: getRiskReminderDate(cutoffAt, settings.riskLeadMinutes),
      subject: `Streak Risk Alert: ${streakName}`,
      title: "Streak Risk Alert",
      body: `${streakName} has a ${currentStreak}-day running streak at risk today.`,
      meta: `Risk threshold: ${settings.riskThresholdDays} days.`,
    });
  }

  if (settings.lastChanceEnabled && cutoffAt) {
    events.push({
      type: "lastchance",
      at: cutoffAt,
      subject: `Last Chance: ${streakName}`,
      title: "Last Chance Reminder",
      body: `Last chance to complete ${streakName} before ${cutoffTime}.`,
      meta: "If not completed today, the active streak can break.",
    });
  }

  const dueEvents = events
    .filter((event) => event.at && formatLocalDate(event.at) === today && now.getTime() >= event.at.getTime())
    .sort((a, b) => a.at.getTime() - b.at.getTime());

  if (!dueEvents.length) {
    return null;
  }

  const event = dueEvents[dueEvents.length - 1];
  return {
    eventKey: `${event.type}:${habit.userId}:${habit.id}:${today}`,
    userId: Number(habit.userId),
    habitId: Number(habit.id),
    eventType: event.type,
    eventDate: today,
    subject: event.subject,
    title: event.title,
    body: event.body,
    meta: event.meta,
  };
}

function buildWeeklyPlanningReminderEvent(userId, habits, settings, now) {
  if (!settings.weeklyPlanningEnabled) {
    return null;
  }
  if (now.getDay() !== 0) {
    return null;
  }

  const weeklyAt = buildDateAtTime(now, settings.weeklyPlanningTime);
  if (!weeklyAt || now.getTime() < weeklyAt.getTime()) {
    return null;
  }

  const today = formatLocalDate(now);
  const activeHabits = (Array.isArray(habits) ? habits : [])
    .filter((habit) => !isHabitCompleted(habit));
  const pendingCount = activeHabits.filter((habit) => {
    if (!isHabitDateInPlan(habit, today)) {
      return false;
    }
    return !new Set(getNormalizedHabitLogs(habit)).has(today);
  }).length;
  const topHabits = activeHabits
    .slice(0, 3)
    .map((habit) => String(habit?.name || "").trim())
    .filter((name) => Boolean(name));

  const title = "Weekly Planning Reminder";
  const body = activeHabits.length
    ? `You have ${activeHabits.length} active streak(s). Pending today: ${pendingCount}.`
    : "You currently have no active streaks. Plan one habit for this week.";
  const meta = topHabits.length
    ? `Top streaks: ${topHabits.join(", ")}${activeHabits.length > 3 ? ", ..." : ""}`
    : "Open dashboard and plan your week.";

  return {
    eventKey: `weekly:${userId}:${today}`,
    userId: Number(userId),
    habitId: null,
    eventType: "weekly_planning",
    eventDate: today,
    subject: "Weekly Habit Planning",
    title,
    body,
    meta,
  };
}

async function claimReminderDeliveryEvent(event) {
  const existing = await db.execute({
    sql: `
      SELECT status
      FROM reminder_delivery_log
      WHERE eventKey = ?
      LIMIT 1
    `,
    args: [event.eventKey],
  });

  if (existing.rows.length > 0) {
    const status = String(existing.rows[0].status || "").toLowerCase();
    if (status === "failed") {
      await db.execute({
        sql: `
          UPDATE reminder_delivery_log
          SET status = 'processing', error = NULL, createdAt = ?
          WHERE eventKey = ?
        `,
        args: [new Date().toISOString(), event.eventKey],
      });
      return true;
    }
    return false;
  }

  const result = await db.execute({
    sql: `
      INSERT INTO reminder_delivery_log (
        eventKey,
        userId,
        habitId,
        eventType,
        eventDate,
        status,
        subject,
        body,
        createdAt
      )
      VALUES (?, ?, ?, ?, ?, 'processing', ?, ?, ?)
      ON CONFLICT(eventKey) DO NOTHING
      RETURNING id
    `,
    args: [
      event.eventKey,
      event.userId,
      event.habitId,
      event.eventType,
      event.eventDate,
      event.subject,
      event.body,
      new Date().toISOString(),
    ],
  });

  return result.rows.length > 0;
}

async function markReminderDeliverySent(eventKey) {
  await db.execute({
    sql: `
      UPDATE reminder_delivery_log
      SET status = 'sent', sentAt = ?, error = NULL
      WHERE eventKey = ?
    `,
    args: [new Date().toISOString(), eventKey],
  });
}

async function markReminderDeliveryFailed(eventKey, errorMessage) {
  await db.execute({
    sql: `
      UPDATE reminder_delivery_log
      SET status = 'failed', error = ?, sentAt = NULL
      WHERE eventKey = ?
    `,
    args: [String(errorMessage || "Unknown reminder delivery error"), eventKey],
  });
}

async function dispatchReminderEvent(event, user) {
  const claimed = await claimReminderDeliveryEvent(event);
  if (!claimed) {
    return false;
  }

  try {
    await sendReminderEmail({
      email: user.email,
      name: user.name || "User",
      subject: event.subject,
      title: event.title,
      body: event.body,
      meta: event.meta || "",
    });
    await markReminderDeliverySent(event.eventKey);
    reminderSentCount += 1;
    return true;
  } catch (error) {
    reminderFailedCount += 1;
    await markReminderDeliveryFailed(event.eventKey, error.message || "Email send failed");
    return false;
  }
}

async function cleanupReminderLogs(now = new Date()) {
  const nowMs = now.getTime();
  if (nowMs - reminderLastCleanupAt < 6 * 60 * 60 * 1000) {
    return;
  }

  const cutoff = new Date(nowMs - REMINDER_LOG_RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await db.execute({
    sql: "DELETE FROM reminder_delivery_log WHERE datetime(createdAt) < datetime(?)",
    args: [cutoff],
  });

  reminderLastCleanupAt = nowMs;
}

async function runReminderEngineTick() {
  if (!REMINDER_ENGINE_ENABLED) {
    return;
  }
  if (reminderTickRunning) {
    return;
  }

  reminderTickRunning = true;
  reminderLastRunAt = new Date().toISOString();

  try {
    const now = new Date();
    const habitsResult = await db.execute({
      sql: `
        SELECT habits.*, users.name AS userName, users.email AS userEmail
        FROM habits
        INNER JOIN users ON users.id = habits.userId
        WHERE habits.archived = 0
          AND (? = 0 OR users.isVerified = 1)
        ORDER BY habits.userId ASC, habits.id DESC
      `,
      args: [EMAIL_VERIFICATION_REQUIRED ? 1 : 0],
    });

    const usersMap = new Map();
    habitsResult.rows.forEach((row) => {
      const habit = normalizeHabit(row);
      const userId = Number(habit.userId);
      if (!Number.isInteger(userId) || userId <= 0) {
        return;
      }

      if (!usersMap.has(userId)) {
        usersMap.set(userId, {
          user: {
            id: userId,
            name: String(row.userName || "User"),
            email: String(row.userEmail || "").trim(),
          },
          habits: [],
        });
      }
      usersMap.get(userId).habits.push(habit);
    });

    const settingsByUser = await getReminderSettingsForUsers(Array.from(usersMap.keys()));

    for (const [userId, data] of usersMap.entries()) {
      if (!data.user.email) {
        continue;
      }

      let settings = settingsByUser.get(userId) || sanitizeReminderSettings(REMINDER_DEFAULTS);
      if (settings.snoozeUntil && !isSnoozeActive(settings, now)) {
        settings = await saveReminderSettingsForUser(userId, { snoozeUntil: null });
      }

      if (isSnoozeActive(settings, now)) {
        continue;
      }
      if (
        settings.quietHoursEnabled &&
        (isAlwaysQuietHours(settings) || isInsideQuietHours(now, settings))
      ) {
        continue;
      }

      const weeklyEvent = buildWeeklyPlanningReminderEvent(
        userId,
        data.habits,
        settings,
        now
      );
      if (weeklyEvent) {
        await dispatchReminderEvent(weeklyEvent, data.user);
      }

      for (const habit of data.habits) {
        const dueEvent = buildDueHabitReminderEvent(habit, settings, now);
        if (!dueEvent) {
          continue;
        }
        await dispatchReminderEvent(dueEvent, data.user);
      }
    }

    await cleanupReminderLogs(now);
    reminderLastError = "";
  } catch (error) {
    reminderLastError = error.message || "Reminder engine tick failed";
    console.error("Reminder engine tick failed:", error);
  } finally {
    reminderTickRunning = false;
    reminderLastRunAt = new Date().toISOString();
  }
}

function startReminderEngine() {
  if (!REMINDER_ENGINE_ENABLED) {
    console.log("Reminder engine disabled by REMINDER_ENGINE_ENABLED=0");
    return;
  }
  if (reminderTicker) {
    return;
  }

  const tickMs = REMINDER_TICK_SECONDS * 1000;
  reminderTicker = setInterval(() => {
    runReminderEngineTick().catch((error) => {
      reminderLastError = error.message || "Reminder engine interval failure";
      console.error("Reminder engine interval failure:", error);
    });
  }, tickMs);

  runReminderEngineTick().catch((error) => {
    reminderLastError = error.message || "Reminder engine startup tick failed";
    console.error("Reminder engine startup tick failed:", error);
  });

  console.log(`Reminder engine started (tick every ${REMINDER_TICK_SECONDS} seconds)`);
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
    const verificationRequired = EMAIL_VERIFICATION_REQUIRED;
    const nowIso = new Date().toISOString();

    if (existingUserResult.rows.length > 0) {
      const existing = existingUserResult.rows[0];

      if (Number(existing.isVerified || 0) === 1) {
        return res.status(409).json({ error: "Email already in use" });
      }

      if (verificationRequired) {
        await db.execute({
          sql: "UPDATE users SET name = ?, passwordHash = ? WHERE id = ?",
          args: [name, passwordHash, existing.id],
        });

        await issueEmailOtpForUser({ userId: Number(existing.id), name, email });

        return res.json({
          message: "OTP sent to your email. Verify before login.",
          email,
          requiresOtp: true,
        });
      }

      await db.execute({
        sql: `
          UPDATE users
          SET name = ?, passwordHash = ?, isVerified = 1, verifiedAt = ?, emailOtpHash = NULL, emailOtpExpiresAt = NULL
          WHERE id = ?
        `,
        args: [name, passwordHash, nowIso, existing.id],
      });

      return res.json({
        message: "Registration successful. You can login now.",
        email,
        requiresOtp: false,
      });
    }

    const createdUserResult = await db.execute({
      sql: `
        INSERT INTO users (name, email, passwordHash, isVerified)
        VALUES (?, ?, ?, ?)
        RETURNING id, name, email, isVerified
      `,
      args: [name, email, passwordHash, verificationRequired ? 0 : 1],
    });

    const user = normalizeUser(createdUserResult.rows[0]);

    if (verificationRequired) {
      await issueEmailOtpForUser({
        userId: user.id,
        name: user.name,
        email: user.email,
      });

      return res.status(201).json({
        message: "Registration successful. OTP sent to your email.",
        email: user.email,
        requiresOtp: true,
      });
    }

    await db.execute({
      sql: "UPDATE users SET verifiedAt = ?, emailOtpHash = NULL, emailOtpExpiresAt = NULL WHERE id = ?",
      args: [nowIso, user.id],
    });

    return res.status(201).json({
      message: "Registration successful. You can login now.",
      email: user.email,
      requiresOtp: false,
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
    if (!EMAIL_VERIFICATION_REQUIRED) {
      const email = String(req.body?.email || "").trim().toLowerCase();
      if (email && isGmailAddress(email)) {
        await db.execute({
          sql: `
            UPDATE users
            SET isVerified = 1, verifiedAt = COALESCE(verifiedAt, ?), emailOtpHash = NULL, emailOtpExpiresAt = NULL
            WHERE email = ?
          `,
          args: [new Date().toISOString(), email],
        });
      }
      return res.json({ message: "Email verification is disabled. Please login directly." });
    }

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
      "If this account exists, a password reset OTP has been sent.";

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
    await issuePasswordResetOtpForUser({
      userId: Number(user.id),
      name: String(user.name || "User"),
      email: String(user.email || email),
    });

    return res.json({ message: genericMessage });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/auth/reset-password", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const email = String(req.body?.email || "").trim().toLowerCase();
    const otp = String(req.body?.otp || "").trim();
    const password = String(req.body?.password || "");

    if (!password) {
      return res.status(400).json({ error: "Password is required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: "Password must be at least 6 characters" });
    }

    const passwordHash = hashPassword(password);

    if (token) {
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
    }

    if (!email || !otp) {
      return res.status(400).json({ error: "Email, OTP, and password are required" });
    }

    if (!isGmailAddress(email)) {
      return res.status(400).json({ error: "Please use a valid Gmail address" });
    }

    if (!/^\d{6}$/.test(otp)) {
      return res.status(400).json({ error: "OTP must be 6 digits" });
    }

    const userResult = await db.execute({
      sql: `
        SELECT id, emailOtpHash, emailOtpExpiresAt
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

    if (!user.emailOtpHash || !user.emailOtpExpiresAt) {
      return res.status(400).json({ error: "OTP not requested. Please request OTP again." });
    }

    if (new Date(user.emailOtpExpiresAt) < new Date()) {
      return res.status(400).json({ error: "OTP expired. Please request OTP again." });
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
        SET passwordHash = ?,
            isVerified = 1,
            verifiedAt = COALESCE(verifiedAt, ?),
            emailOtpHash = NULL,
            emailOtpExpiresAt = NULL,
            resetPasswordTokenHash = NULL,
            resetPasswordExpiresAt = NULL
        WHERE id = ?
      `,
      args: [passwordHash, new Date().toISOString(), user.id],
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

    if (EMAIL_VERIFICATION_REQUIRED && Number(row.isVerified || 0) !== 1) {
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

app.get("/api/reminders/settings", requireAuth, async (req, res) => {
  try {
    const settings = await getReminderSettingsForUser(req.auth.user.id);
    return res.json({ settings });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.put("/api/reminders/settings", requireAuth, async (req, res) => {
  try {
    const payload = req.body && typeof req.body === "object" ? req.body : {};

    if (
      payload.followUpDelayMinutes !== undefined &&
      (!Number.isInteger(Number(payload.followUpDelayMinutes)) ||
        Number(payload.followUpDelayMinutes) < 5 ||
        Number(payload.followUpDelayMinutes) > 360)
    ) {
      return res.status(400).json({ error: "followUpDelayMinutes must be between 5 and 360" });
    }

    if (
      payload.lastChanceTime !== undefined &&
      !isValidTimeHHMM(payload.lastChanceTime)
    ) {
      return res.status(400).json({ error: "lastChanceTime must be in HH:MM format" });
    }

    if (
      payload.riskThresholdDays !== undefined &&
      (!Number.isInteger(Number(payload.riskThresholdDays)) ||
        Number(payload.riskThresholdDays) < 1 ||
        Number(payload.riskThresholdDays) > 3650)
    ) {
      return res.status(400).json({ error: "riskThresholdDays must be between 1 and 3650" });
    }

    if (
      payload.riskLeadMinutes !== undefined &&
      (!Number.isInteger(Number(payload.riskLeadMinutes)) ||
        Number(payload.riskLeadMinutes) < 5 ||
        Number(payload.riskLeadMinutes) > 360)
    ) {
      return res.status(400).json({ error: "riskLeadMinutes must be between 5 and 360" });
    }

    if (
      payload.weeklyPlanningTime !== undefined &&
      !isValidTimeHHMM(payload.weeklyPlanningTime)
    ) {
      return res.status(400).json({ error: "weeklyPlanningTime must be in HH:MM format" });
    }

    if (
      payload.quietHoursStart !== undefined &&
      !isValidTimeHHMM(payload.quietHoursStart)
    ) {
      return res.status(400).json({ error: "quietHoursStart must be in HH:MM format" });
    }

    if (
      payload.quietHoursEnd !== undefined &&
      !isValidTimeHHMM(payload.quietHoursEnd)
    ) {
      return res.status(400).json({ error: "quietHoursEnd must be in HH:MM format" });
    }

    if (
      payload.snoozeMinutes !== undefined &&
      (!Number.isInteger(Number(payload.snoozeMinutes)) ||
        Number(payload.snoozeMinutes) < 5 ||
        Number(payload.snoozeMinutes) > 720)
    ) {
      return res.status(400).json({ error: "snoozeMinutes must be between 5 and 720" });
    }

    if (
      payload.snoozeUntil !== undefined &&
      payload.snoozeUntil !== null &&
      payload.snoozeUntil !== "" &&
      !normalizeSnoozeUntil(payload.snoozeUntil)
    ) {
      return res.status(400).json({ error: "snoozeUntil must be a valid ISO date or null" });
    }

    const settings = await saveReminderSettingsForUser(req.auth.user.id, payload);
    return res.json({
      message: "Reminder settings updated",
      settings,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/reminders/snooze", requireAuth, async (req, res) => {
  try {
    const current = await getReminderSettingsForUser(req.auth.user.id);
    const requestedMinutes = req.body?.minutes;
    const minutes =
      requestedMinutes === undefined || requestedMinutes === null || String(requestedMinutes).trim() === ""
        ? current.snoozeMinutes
        : Number(requestedMinutes);

    if (!Number.isInteger(minutes) || minutes < 5 || minutes > 720) {
      return res.status(400).json({ error: "minutes must be an integer between 5 and 720" });
    }

    const snoozeUntil = new Date(Date.now() + minutes * 60 * 1000).toISOString();
    const settings = await saveReminderSettingsForUser(req.auth.user.id, {
      snoozeMinutes: minutes,
      snoozeUntil,
    });

    return res.json({
      message: "Reminders snoozed",
      snoozeUntil,
      settings,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.delete("/api/reminders/snooze", requireAuth, async (req, res) => {
  try {
    const settings = await saveReminderSettingsForUser(req.auth.user.id, {
      snoozeUntil: null,
    });
    return res.json({
      message: "Snooze cleared",
      settings,
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

app.post("/api/reminders/trigger-now", requireAuth, async (req, res) => {
  try {
    await runReminderEngineTick();
    return res.json({
      message: "Reminder engine tick executed",
      status: {
        enabled: REMINDER_ENGINE_ENABLED,
        tickSeconds: REMINDER_TICK_SECONDS,
        running: reminderTickRunning,
        lastRunAt: reminderLastRunAt,
        lastError: reminderLastError || null,
        sentCount: reminderSentCount,
        failedCount: reminderFailedCount,
      },
    });
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

app.post("/api/send-email", async (req, res) => {
  const googleScriptUrl =
    GOOGLE_SCRIPT_WEBHOOK_URL ||
    "https://script.google.com/macros/s/AKfycbzMKm4wdFlshWl7UfRrjqj5Q3ex7I2YsvhZa9k2vGherhGZc0lrDbhLFrG6R2thWq_98w/exec";
  const { to, subject, body } = req.body || {};

  if (!to || !subject || !body) {
    return res.status(400).json({
      success: false,
      message: "Missing required fields: to, subject, or body",
    });
  }

  try {
    const response = await fetch(googleScriptUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        to: String(to),
        subject: String(subject),
        body: String(body),
      }),
    });

    const responseText = await response.text();
    let result = {};
    try {
      result = responseText ? JSON.parse(responseText) : {};
    } catch {
      result = {};
    }

    if (!response.ok) {
      return res.status(500).json({
        success: false,
        error: result.error || `Webhook failed with status ${response.status}`,
      });
    }

    if (result.success === false) {
      return res.status(500).json({ success: false, error: result.error || "Webhook rejected request" });
    }

    return res
      .status(200)
      .json({ success: true, message: "Email sent successfully via Google Webhook!" });
  } catch (error) {
    console.error("Webhook Error:", error);
    return res.status(500).json({
      success: false,
      error: "Failed to reach Google Script",
      details: error.message,
    });
  }
});

app.get("/ping", (req, res) => {
  res.status(200).json({ status: "success", message: "StreakUps is awake!" });
});

app.get("/api/health", (req, res) => {
  res.json({
    ok: true,
    service: "streak-backend",
    reminders: {
      enabled: REMINDER_ENGINE_ENABLED,
      tickSeconds: REMINDER_TICK_SECONDS,
      running: reminderTickRunning,
      lastRunAt: reminderLastRunAt,
      lastError: reminderLastError || null,
      sentCount: reminderSentCount,
      failedCount: reminderFailedCount,
    },
  });
});

app.get("/", (req, res) => {
  res.sendFile(path.join(FRONTEND_DIR, "index.html"));
});

initDB().then(() => {
  startReminderEngine();
  app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
  });
});
