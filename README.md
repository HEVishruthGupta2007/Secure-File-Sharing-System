# CODSOFT_TASK5 — Secure File Sharing System

A Flask backend for authenticated, encrypted file sharing, built for the
CodSoft Cyber Security Internship.

## What it does

- **Authentication** — register/login with hashed passwords (Flask-Login +
  Werkzeug's PBKDF2 hashing). The first account created becomes an admin.
- **Encryption at rest** — every file gets its own random key at upload
  time; the file is encrypted with that key before it's written to disk,
  and the key itself is encrypted ("wrapped") with a master key before
  being stored in the database. This is envelope encryption: even a full
  copy of the database is useless without the separate master key, and no
  two files ever share a key.
- **Role-based access control** — `admin` accounts see and manage every
  file; regular users only see files they own or that were explicitly
  shared with them. A single `can_access()` function is the one place
  every access decision gets made.
- **Temporary download links** — generate a tokenised link with a chosen
  expiry (1 minute to 7 days). No login required to use it; it stops
  working the moment it expires (HTTP 410 Gone).

## Folder structure

```
CODSOFT_TASK5/
├── run.py                 entry point
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── app/
    ├── __init__.py         app factory
    ├── config.py           settings, master key loading
    ├── extensions.py       db, login_manager
    ├── models.py           User, FileRecord, FileShare, ShareLink
    ├── crypto_utils.py     envelope encryption helpers
    ├── auth/
    │   ├── __init__.py
    │   └── routes.py       register, login, logout
    ├── files/
    │   ├── __init__.py
    │   └── routes.py       upload, download, share, temp links
    └── templates/          base, login, register, dashboard
```

`uploads/` (encrypted file blobs) and `instance/` (the SQLite database) are
created automatically on first run and are git-ignored — nothing sensitive
ends up in the repo.

## Setup

### 1. Create and Activate Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts scripts, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` first)*

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

```bash
# macOS/Linux
cp .env.example .env

# Windows
copy .env.example .env
```

Generate a secure master Fernet key:
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```
Open `.env` and replace `paste-your-generated-fernet-key-here` with the generated key.

### 4. Run the Application

> **Note for Windows users:** Always run the application with `python run.py`. Do not double-click `run.py` or type `run.py` directly into PowerShell (which may launch an external editor instead of running the script in the active virtual environment).

```bash
python run.py
```
Visit `http://127.0.0.1:5001` in your browser.

Register an account — the first one created becomes an admin automatically.
Register a second account in a different browser (or incognito window) to
demonstrate sharing between two real users.

## How the pieces fit together

**Envelope encryption** (`crypto_utils.py`): a naive design would encrypt
every file with one fixed key. The problem is that one leaked key then
decrypts everything ever uploaded. Instead, each file gets its own
throwaway key, and only that small key — not the file — gets encrypted
with the master key for storage. Compromising the database alone reveals
nothing without the master key, which lives only in `.env`, never in git
or the database.

**RBAC** (`files/routes.py`, `can_access()`): three tiers — admin (sees
everything), owner (always has full access to their own files), and
share-grant holders (access to exactly the files explicitly shared with
them, at `view` or `download` permission). Every route that touches a
specific file checks this function before doing anything else.

**Temporary links** (`ShareLink` model): a random token, an expiry
timestamp, and one route that needs no login at all — the token itself is
the credential. Past its expiry, the same link returns 410 Gone.

## Tested end to end

Before this was written up, every core flow was run through a Flask test
client: register two users, upload a file, confirm the bytes on disk are
genuinely encrypted (not just base64 or similarly reversible), confirm a
non-owner is blocked with 403, confirm sharing grants access, confirm a
temporary link works without login, and confirm it correctly stops working
once expired.

## Legal / ethical note

This is a learning project. Before using anything like this for real
sensitive data, add HTTPS (a reverse proxy such as nginx with TLS),
rate-limiting on login attempts, and a production-grade secret manager for
the master key instead of a `.env` file.

---
Submitted as part of the **CodSoft Cyber Security Internship** — `#codsoft`
