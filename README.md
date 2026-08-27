# SecureBankPrototype

**Secure Retail Online Banking System with End-to-End Cryptographic Protection**

SecureBankPrototype is a cybersecurity coursework demo built with a Flask JSON API and a React (Vite) frontend, backed by SQLite. It models a secure retail internet banking portal (registration, OTP login, account balances, transfers, transaction history, profile management) to demonstrate real authentication and transaction-protection mechanisms — not a core banking system (no savings/fixed-deposit/loan products) and not connected to any real bank.

Each customer has one Current Account (identified by a system-generated account number) and an optional Digital Wallet, funded by an internal top-up from the Current Account. Transfers move simulated money between two demo accounts, validated by account number, and are protected by hashing, symmetric encryption, asymmetric key wrapping, and a digital signature before being written to the database.

## Features Implemented

- User registration with password complexity checks and SHA-256 password hashing for this coursework prototype
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
- Encrypted SQLite backup to `backups/bank_backup.db.enc`, with a separate SHA-256 integrity manifest
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

### Algorithm level

The prototype demonstrates the following algorithm-level mechanisms:

- **SHA-256 hashing:** Password hashes, transfer payload hashes, and backup integrity manifests.
- **AES-256-CBC:** Symmetric encryption/decryption of transfer amounts, messages, encryption-lab data, and full database backup snapshots. Each encryption uses a randomly generated IV and a randomly generated 256-bit AES key.
- **RSA-2048-OAEP:** Asymmetric encryption/decryption used to wrap the per-transfer AES key.
- **RSA-SHA256 digital signatures:** Transfer payloads are signed with the RSA private key and verified with the public key before the transaction is stored.
- **TOTP MFA:** `pyotp` generates and verifies a time-based one-time password after the password check.
- **Password controls:** Complexity validation, failed-login counting, and temporary account lockout.

### Protocol level

- **HTTP/HTTPS web transfer:** The React frontend communicates with the Flask JSON API using `fetch` and credentialed session cookies. HTTPS is supported through the local `cert.pem` and `key.pem` certificate pair.
- **TLS demonstration:** When certificates are present, Flask serves the API over HTTPS. For local HTTP development, the README labels this as demo mode.
- **Session and cross-origin controls:** `HttpOnly`, `Secure`, `SameSite=None` session-cookie settings are used for the HTTPS frontend/API setup, with a restricted CORS origin.
- **Secure report transfer:** The generated security report is downloaded through the application over HTTP or HTTPS.
- **Secure mail and file-transfer protocols:** SMTP/SMTPS, IMAP, FTP/FTPS, and SFTP are not implemented because this prototype has no email or external file-transfer workflow. The OTP is returned in the login response for demonstration only.

### System level

- **System backup:** An authorized security/admin user can create an AES-encrypted SQLite snapshot, store a SHA-256 manifest, decrypt it in memory, and verify that the restored bytes match the original hash.
- **Firewall monitoring:** The application reads Windows Defender Firewall profile/rule status through PowerShell and can read `pfirewall.log` when Windows grants access. It does not change firewall rules.
- **IDS-style monitoring:** Login failures, OTP failures, transfer failures, and attack simulations are written to `logs/security.log` and surfaced in the Security Operations Center. This is application security-event monitoring, not a dedicated network IDS/IPS.
- **Role-based access control:** Customer, security, and admin roles protect banking and security operations endpoints.
- **Audit evidence:** Security logs, attack simulation results, encryption-lab output, database viewer, backup center, and a downloadable security report provide demonstrable CW2 evidence.

### Prototype limitations

- The application uses SHA-256 for passwords to satisfy the coursework demonstration; production banking software should use a salted adaptive password hash such as Argon2id, bcrypt, or scrypt.
- AES-CBC is retained for the current coursework implementation; production systems should use authenticated encryption such as AES-GCM and verify stored transaction integrity on every read.
- The SQLite database is not encrypted as a whole; selected transaction fields and backup snapshots are encrypted.
- The local backup key is stored with the prototype backup files for demonstration and must be moved to protected key storage in production.
- Windows Firewall integration, IDS monitoring, HTTPS certificates, and backups depend on local operating-system configuration and permissions.
- This prototype does not connect to real banking, mail, payment, or external file-transfer services.
