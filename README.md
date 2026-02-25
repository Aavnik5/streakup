# streakupbackend

Node + Turso backend for Streak Up.

## Reminder Engine (Backend Background)

This backend now runs a server-side reminder engine (email-based), so reminders can be sent even when the browser app is closed.

### Supported reminder logic

- Primary reminder: each streak `reminderTime`
- Follow-up nudge: only if today's streak is still pending
- Last chance: at user cutoff time (default `22:30`)
- Streak risk alert: when current streak is high and still pending
- Weekly planning: Sunday reminder (default `18:00`)
- Quiet hours and Snooze: user-controlled

### Environment variables

- `REMINDER_ENGINE_ENABLED` (`1` default, set `0` to disable)
- `REMINDER_TICK_SECONDS` (`60` default, minimum `15`)
- `REMINDER_LOG_RETENTION_DAYS` (`90` default, minimum `7`)
- `EMAIL_VERIFICATION_REQUIRED` (`0` default, set `1` to enforce OTP verification before login)
- Existing mail settings are required for delivery:
  - `GMAIL_USER`
  - `GMAIL_APP_PASSWORD`
  - `MAIL_FROM` (optional fallback to `GMAIL_USER`)
  - SMTP tuning (optional):
    - `SMTP_HOST` (default `smtp.gmail.com`)
    - `SMTP_PORT` (default `465`)
    - `SMTP_SECURE` (`1` default)
    - `SMTP_FAMILY` (`4` default)
  - Provider selection:
    - `EMAIL_PROVIDER` (`auto` default, `smtp`, or `resend`)
    - `RESEND_API_KEY` (required for `resend`, and for `auto` fallback on SMTP failure)
    - `RESEND_FROM` (default `onboarding@resend.dev`)
    - `RESEND_API_URL` (default `https://api.resend.com/emails`)

### Reminder APIs

All endpoints below require auth token (`Bearer <token>`):

- `GET /api/reminders/settings`
- `PUT /api/reminders/settings`
- `POST /api/reminders/snooze`
- `DELETE /api/reminders/snooze`
- `POST /api/reminders/trigger-now` (manual tick)

Health check includes reminder engine status:

- `GET /api/health`

### Notes

- Delivery is email-based in this version.
- Render free plan blocks outbound SMTP ports, so use `EMAIL_PROVIDER=resend` for OTP/recovery/reminders.
- On free hosting plans that sleep services, background reliability may still degrade while instance is asleep.
