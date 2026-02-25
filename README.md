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
- Existing mail settings are required for delivery:
  - `GMAIL_USER`
  - `GMAIL_APP_PASSWORD`
  - `MAIL_FROM` (optional fallback to `GMAIL_USER`)

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
- On free hosting plans that sleep services, background reliability may still degrade while instance is asleep.
