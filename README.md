# CipherVault — Secure File Sharing System

A complete, working Flask prototype that demonstrates secure authentication, **AES-256-GCM encrypted file storage**, controlled file sharing with granular permissions, activity auditing and administrator oversight.

> Designed as a cybersecurity / secure document management project. All security checks are enforced on the backend — hiding buttons in the UI is never treated as a control.

---

## Feature Highlights

- **Authentication** — registration, login, logout, session management, Werkzeug password hashing (never plaintext), email + username uniqueness, account activation control.
- **Roles** — `Administrator` and `Normal User`; normal users are blocked from all admin routes (403 + security event).
- **Dashboard** — real database statistics (files, shares sent/received, storage used), 7-day upload chart, sharing breakdown, recent activity and recent shared files.
- **File management** — upload, list, search, sort, preview, download, details, delete; server-side extension allow-list, content signature validation, configurable size limit and unique random storage filenames.
- **Encryption** — every upload is encrypted in memory with **AES-256-GCM** using a fresh 96-bit nonce; ciphertext is stored outside `static/` in `instance/secure_files/`. The key comes from `FILE_ENCRYPTION_KEY` and is never stored in the database or source code.
- **Sharing & permissions** — share by recipient email; **View only** (preview, no download) or **Download**; duplicate grants update the existing record; owners can revoke instantly; revoked access is rejected on every backend request.
- **Shared With Me / Shared By Me / Manage Permissions** — complete sharing management pages.
- **Audit & security monitoring** — activity logs (login, logout, upload, download, preview, delete, share, permission changes, revocations, unauthorized attempts) with search/filtering; security events for failed logins, unauthorized access and decryption/integrity failures; admins can view system-wide activity.
- **Administrator dashboard** — users, active users, files, shared files, platform charts, recent security events, user activation/deactivation.
- **Responsive UI** — dark navy sidebar, light workspace, Bootstrap 5, Bootstrap Icons, Chart.js, mobile offcanvas-style navigation.
- **Automated tests** — 33 passing pytest tests covering authentication, encryption, permission enforcement, revocation, tampering detection, admin authorization and activity logging.

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3, Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF, Flask-Migrate |
| Database | SQLite |
| Frontend | HTML5, CSS3, JavaScript, Bootstrap 5, Bootstrap Icons, Chart.js |
| Security | Werkzeug password hashing, `cryptography` AES-256-GCM, CSRF protection, secure sessions, RBAC, backend permission checks |
| Testing | pytest |

---

## Project Structure

```
COMPREHENSION/
├── app/
│   ├── __init__.py            # application factory, error handlers, filters, context
│   ├── extensions.py          # db, login manager, migrate, csrf
│   ├── models.py              # User, File, FilePermission, ActivityLog, SecurityEvent
│   ├── forms.py               # WTForms (auth, profile, upload, share)
│   ├── timeutils.py           # naive-UTC timestamp helper
│   ├── cli.py                 # init-db, create-admin, generate-key commands
│   ├── auth/
│   │   ├── __init__.py
│   │   └── routes.py          # /register /login /logout
│   ├── dashboard/
│   │   ├── __init__.py
│   │   └── routes.py          # /dashboard /profile /activity-logs
│   ├── files/
│   │   ├── __init__.py
│   │   └── routes.py          # /files ...
│   ├── sharing/
│   │   ├── __init__.py
│   │   └── routes.py          # /sharing ...
│   ├── admin/
│   │   ├── __init__.py
│   │   └── routes.py          # /admin ...
│   ├── security/
│   │   ├── __init__.py
│   │   ├── encryption.py      # AES-256-GCM + key validation
│   │   ├── permissions.py     # backend authorization helpers
│   │   ├── audit.py           # activity + security event logging
│   │   └── file_validation.py # extension/content validation
│   ├── templates/
│   │   ├── base.html
│   │   ├── auth_base.html
│   │   ├── _macros.html
│   │   ├── auth/
│   │   ├── dashboard/
│   │   ├── files/
│   │   ├── sharing/
│   │   ├── admin/
│   │   └── errors/
│   └── static/
│       ├── css/style.css
│       ├── images/favicon.svg
│       └── js/app.js
├── instance/
│   └── secure_files/          # encrypted ciphertext (outside static)
├── migrations/                # Flask-Migrate migrations
├── tests/                     # pytest suite
├── config.py
├── run.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

---

## Quick Start (Windows / VS Code)

Open **PowerShell** in the project folder:

```powershell
cd C:\Users\BENJAMIN\PycharmProjects\COMPREHENSION
```

### 1. Create and activate a virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run once:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 2. Install dependencies

```powershell
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure environment variables

A local `.env` is already present in this working copy (it is gitignored). For a fresh checkout:

```powershell
Copy-Item .env.example .env
```

Generate secrets and paste them into `.env`:

```powershell
# Flask session key
python -c "import secrets; print(secrets.token_hex(32))"

# AES-256-GCM key (requires the app package; Flask emits a warning if the key is absent, which is fine here)
flask --app run.py generate-key
```

Edit `.env`:

```ini
SECRET_KEY=<paste session key>
FILE_ENCRYPTION_KEY=<paste generated AES key>
SESSION_COOKIE_SECURE=False
MAX_CONTENT_LENGTH=26214400
```

> The AES key must decode to exactly 32 bytes (the `generate-key` command guarantees this).
> **Never commit `.env` or the encryption key. Losing the key makes existing ciphertext unrecoverable.**

### 4. Create the database

```powershell
# Option A — migrations (recommended)
flask --app run.py db upgrade

# Option B — create tables directly
flask --app run.py init-db
```

### 5. Create the first administrator

Public registration always creates a **normal user**. The first admin is created from the command line:

```powershell
flask --app run.py create-admin
```

You will be prompted for full name, username, email and a password (minimum 8 characters, at least one letter and one number).

### 6. Run the application

```powershell
python run.py
```

Open **http://127.0.0.1:5000** and sign in. Register a normal account to test sharing, or use the administrator account created above.

---

## Running the Tests

```powershell
pytest -q
```

The tests use an isolated temporary SQLite database, a temporary upload folder and a freshly generated encryption key, so they never touch your real data.

Covered scenarios include:

1. Registration + password hashing (no plaintext storage)
2. Duplicate email / weak password rejection
3. Login success/failure and deactivated-account blocking
4. Upload + AES-256-GCM encryption at rest
5. Download decryption round-trip
6. Non-owner download blocked (403 + security event)
7. View-only permission allows preview, blocks download
8. Download permission allows download
9. Revocation blocks access immediately and hides file from “Shared With Me”
10. Duplicate sharing updates a single permission record
11. Non-owner cannot share or revoke someone else's file
12. Tampered ciphertext fails GCM authentication and is not served
13. Normal users cannot access admin routes
14. Administrators can activate/deactivate users but not themselves
15. Activity logs record actions and normal users only see their own
16. File deletion removes both metadata and ciphertext

---

## Main Routes

### Authentication

| Method | Route | Description |
|---|---|---|
| GET/POST | `/register` | Create a normal user account |
| GET/POST | `/login` | Sign in with username or email |
| POST | `/logout` | End the session (CSRF-protected) |

### Dashboard / Account

| Method | Route | Description |
|---|---|---|
| GET | `/` | Redirect to dashboard or login |
| GET | `/dashboard` | Statistics, charts and recent activity |
| GET/POST | `/profile` | Update profile / change password |
| GET | `/activity-logs` | Personal audit trail (system-wide for admins) |

### Files

| Method | Route | Description |
|---|---|---|
| GET | `/files` | List / search / sort own files |
| GET/POST | `/files/upload` | Validate, encrypt and store a file |
| GET | `/files/<id>` | File details (owner, active recipient or admin) |
| GET | `/files/<id>/download` | Permission-checked decrypt + download |
| GET | `/files/<id>/preview` | Permission-checked inline preview |
| POST | `/files/<id>/delete` | Owner-only delete (metadata + ciphertext) |

### Sharing

| Method | Route | Description |
|---|---|---|
| GET/POST | `/sharing/share/<file_id>` | Grant access by recipient email |
| GET | `/sharing/shared-with-me` | Active files shared with the current user |
| GET | `/sharing/shared-by-me` | All grants created by the current user |
| GET | `/sharing/permissions` | Files available for permission management |
| GET | `/sharing/permissions/<file_id>` | Permission records for one file |
| POST | `/sharing/revoke/<permission_id>` | Owner-only revocation |

### Administration

| Method | Route | Description |
|---|---|---|
| GET | `/admin/dashboard` | Platform statistics and security snapshot |
| GET | `/admin/users` | User list / filters |
| POST | `/admin/users/<id>/toggle` | Activate or deactivate an account |
| GET | `/admin/files` | All file metadata |
| GET | `/admin/security` | Security event monitoring |

All non-auth routes require an authenticated session. All admin routes require the `admin` role — enforced server-side by `admin_required`.

---

## Encryption Design

```
plaintext bytes
      │
      ├── fresh 12-byte nonce (os.urandom)
      ├── AES-256-GCM encrypt (key from FILE_ENCRYPTION_KEY, AAD = "SFSE\x01")
      ▼
MAGIC (5) │ NONCE (12) │ CIPHERTEXT + GCM TAG
      ▼
instance/secure_files/<random-uuid>.enc
```

- The database stores only metadata; it never stores file content.
- The original filename is kept for display/download headers, but the physical file uses a random UUID.
- Before any read, the backend re-checks ownership or an active permission record.
- GCM authentication detects tampering; failed decryption returns a generic error and records a `decryption_failure` security event.
- Keys are loaded from the environment. There is no fallback hardcoded key.

---

## Security Controls Implemented

| Control | Implementation |
|---|---|
| Password hashing | `werkzeug.security.generate_password_hash` (salted) |
| File encryption | AES-256-GCM via `cryptography`, random nonce per file |
| Key management | `FILE_ENCRYPTION_KEY` environment variable only |
| CSRF protection | Flask-WTF `CSRFProtect` on all POST requests |
| Session security | HttpOnly, SameSite=Lax, optional Secure cookies, 8-hour session lifetime, 14-day opt-in “remember me”, strong session protection |
| Authentication | Flask-Login `@login_required`, safe `next` redirects, deactivation invalidates existing sessions |
| Authorization | `admin_required`, owner checks, active-permission checks on preview/download |
| Upload validation | Allow-list, signature checks, size limit, empty-file rejection |
| Storage isolation | Ciphertext outside the static/web root; random filenames |
| Path traversal | Resolved storage paths are constrained to the upload directory |
| SQL injection | SQLAlchemy ORM parameterization |
| XSS | Jinja auto-escaping; inline previews sent with `nosniff` |
| Audit | Activity logs + security events with IP and timestamp |
| Error hygiene | Generic 500 page; no keys, passwords or stack traces exposed |
| Role escalation | Registration forces `user`; admins only via CLI |

---

## Configuration Reference (`.env`)

| Variable | Purpose | Default |
|---|---|---|
| `SECRET_KEY` | Flask session signing | dev fallback (change it) |
| `FILE_ENCRYPTION_KEY` | AES-256-GCM key (base64, 32 bytes) | none — required |
| `DATABASE_URL` | Optional database URI | `sqlite:///instance/secure_file_sharing.db` |
| `UPLOAD_FOLDER` | Optional encrypted storage folder | `instance/secure_files` |
| `MAX_CONTENT_LENGTH` | Max upload bytes | `26214400` (25 MB) |
| `SESSION_COOKIE_SECURE` | Send cookies only over HTTPS | `False` (set `True` in production) |

---

## Production Notes

This is a security-focused **prototype**, not a certified product. For production deployment:

- Serve over **HTTPS** (reverse proxy + TLS) and set `SESSION_COOKIE_SECURE=True`.
- Run behind a production WSGI server (e.g. Waitress on Windows or Gunicorn on Linux), not the Flask dev server.
- Use a proxy that sets `X-Forwarded-For` correctly; the app logs the first forwarded address.
- Back up the encryption key separately from the database and ciphertext. Without the key, files cannot be recovered.
- Consider key rotation/versioning, rate limiting, MFA, email verification, malware scanning and object storage for scale.
- SQLite is suitable for a prototype/single instance; use PostgreSQL for multi-user production.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | Activate `.venv` and run `pip install -r requirements.txt` |
| “FILE_ENCRYPTION_KEY is not configured” | Add a valid key from `flask --app run.py generate-key` to `.env` |
| Uploads fail with encryption error | Key is missing/malformed; it must be URL-safe base64 of 32 bytes |
| `flask: command not found` | Use `python -m flask --app run.py ...` |
| Database tables missing | Run `flask --app run.py db upgrade` or `init-db` |
| Can't access admin pages | Create an admin with `flask --app run.py create-admin` (registration only creates normal users) |
| Files disappear after revoke | Expected: revoked permissions are filtered out on every request |

---

## License / Academic Use

Created as a secure file-sharing prototype for educational and demonstration purposes. Review and harden before any real-world deployment.
