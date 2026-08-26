# SecureBankPrototype

**Secure Retail Online Banking System with End-to-End Cryptographic Protection**

SecureBankPrototype is a cybersecurity coursework demo built with a Flask JSON API and a React (Vite) frontend, backed by SQLite. It models a secure retail internet banking portal (registration, OTP login, account balances, transfers, transaction history, profile management) to demonstrate real authentication and transaction-protection mechanisms — not a core banking system (no savings/fixed-deposit/loan products) and not connected to any real bank.

Each customer has one Current Account (identified by a system-generated account number) and an optional Digital Wallet, funded by an internal top-up from the Current Account. Transfers move real money between two real accounts, validated by account number, and are further secured end-to-end (SHA-256, AES-256, RSA-OAEP, RSA-SHA256 signature) before being written to the database.

## Features Implemented

- User registration with password complexity checks and SHA-256 hashing
- Login with account lockout after repeated failures
- OTP second-factor verification using `pyotp`
- Session-based authentication and access control (`Flask-Login`), consumed by the React SPA via `credentials: include` fetch calls
- Dashboard, transfer page, transaction history, and profile page
- Security Operations Center dashboard with animated network topology, live encryption monitor, timeline, and threat map
- Encryption laboratory, attack simulation lab, database viewer, backup center, security logs, and downloadable security report
- Secure transfer pipeline:
  - AES-256 encrypts transfer amount and message
  - RSA-OAEP encrypts AES key
  - RSA-SHA256 digital signature signs transaction payload
  - Signature is verified before storage
- Activity logging to `logs/security.log`
- Admin panel (optional feature) for users, transactions, logs, and backups
- SQLite backup to `backups/bank_backup.db`
- HTTPS-ready local run using self-signed certificate files if provided

## Project Structure

```
SecureBankPrototype/
  app.py                # Flask JSON API
  config.py
  requirements.txt
  database/
  security/              # hashing, AES, RSA, signatures, OTP, certificate
  backups/
  logs/
  frontend/              # React (Vite) SPA
    src/
      pages/             # Login, Register, Otp, Dashboard, Transfer, ...
      components/        # AppShell (sidebar layout), route guards
      context/           # AuthContext (session state)
      api.js             # fetch wrapper for the Flask API
      theme.css          # custom card/sidebar styling on top of Bootstrap
  README.md
```

## Running the app (two processes)

### 1. Backend (Flask API) — `SecureBankPrototype/`

```bash
pip install -r requirements.txt
python app.py
```

The API runs on `http://127.0.0.1:5000` (or `https://127.0.0.1:5000` when `cert.pem`/`key.pem` exist in the project root — see below). All routes are under `/api/*` and return JSON.

### 2. Frontend (React SPA) — `SecureBankPrototype/frontend/`

```bash
cd frontend
npm install
npm run dev
```

The SPA runs on `http://localhost:5173` and talks to the Flask API via the URL in `frontend/.env` (`VITE_API_BASE`, defaults to `http://localhost:5000/api`).

> Run the Flask API over plain HTTP during local development (leave `cert.pem`/`key.pem` out of the project root). Mixing an HTTPS API origin with an HTTP Vite dev server causes browsers to block the session cookie. Use the self-signed certificate separately (e.g. via `curl -k` or Postman) to demonstrate the TLS/HTTPS requirement directly against the API.

## Default Admin Account

A default admin account is auto-created when the Flask app first starts.

- Username: `admin`
- Password: `Admin@123`

Change this in code for your submission/demo.

## Generate Self-Signed TLS Certificate (Windows OpenSSL)

If OpenSSL is available:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes
```

Place `cert.pem` and `key.pem` in the project root.

## Security Notes

- SHA-256 is used because it matches coursework requirements.
- In production systems, use adaptive password hashing (Argon2/bcrypt/scrypt).
- OTP is returned directly in the `/api/login` response for demo convenience (no SMS/email integration).
- This prototype does not connect to real bank APIs.
