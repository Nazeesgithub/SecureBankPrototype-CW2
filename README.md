# SecureBankPrototype

**Secure Retail Online Banking System with End-to-End Cryptographic Protection**

SecureBankPrototype is a cybersecurity coursework demo built with a Flask JSON API and a React (Vite) frontend, backed by SQLite. It models a secure retail internet banking portal (registration, OTP login, account balances, transfers, transaction history, profile management) to demonstrate real authentication and transaction-protection mechanisms — not a core banking system (no savings/fixed-deposit/loan products) and not connected to any real bank.

Each customer has one Current Account (identified by a system-generated account number) and an optional Digital Wallet, funded by an internal top-up from the Current Account. Transfers move simulated money between two demo accounts, validated by account number, and are protected by hashing, symmetric encryption, asymmetric key wrapping, and a digital signature before being written to the database.

## Features Implemented

- User registration with password complexity checks and salted scrypt password hashing
- Login with account lockout after repeated failures
- OTP second-factor verification using `pyotp`, enrollable into Google/Microsoft Authenticator through `GET /api/profile/otp-uri` (the code is never returned by the login endpoint unless `DEMO_MODE=true`)
- Session-based authentication and access control (`Flask-Login`), consumed by the React SPA via `credentials: include` fetch calls
- Dashboard, transfer page, transaction history, and profile page
- Security Operations Center dashboard with animated network topology, live encryption monitor, timeline, and threat map
- Encryption laboratory, attack simulation lab, database viewer, backup center, security logs, and downloadable security report
- Secure transfer pipeline:
  - AES-256 encrypts transfer amount and message
  - RSA-OAEP encrypts AES key
  - RSASSA-PSS (SHA-256) digital signature signs the transaction payload
  - Signature is verified before storage
- Secure mail over SMTP+STARTTLS (`security/mailer.py`) delivering the login OTP
  and transfer confirmations, with the negotiated TLS version and cipher logged
- Offsite encrypted-backup transfer over SFTP (`security/sftp_backup.py`) with
  mandatory SSH host key verification and the negotiated cipher/MAC logged
- HTTPS by default on both processes, plus HSTS, CSP, `nosniff`, `X-Frame-Options`
  and `Referrer-Policy` response headers
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
  security/              # hashing, AES, RSA, signatures, OTP, certificate,
                         # mailer (SMTP+STARTTLS), sftp_backup (SFTP)
  scripts/
    generate_cert.py     # self-signed TLS certificate with SAN
    test_race.py         # concurrency proof for the transfer endpoint
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

## Quick start (first run, from a fresh copy)

This exact sequence was verified against a clean copy of the repository with
no database, no RSA keys, no TLS certificate, no `.secret_key` and no
`node_modules`. Follow it in order and everything below works.

```bash
# 1. Dependencies and the TLS certificate
pip install -r requirements.txt
python scripts/generate_cert.py

# 2. Start the API with the two settings a first run needs (PowerShell)
$env:DEMO_MODE = "true"
$env:BACKUP_PASSPHRASE = "demo-backup-passphrase"
python app.py

# 3. In a second terminal, start the SPA
cd frontend
npm install
npm run dev
```

bash equivalent for step 2:

```bash
DEMO_MODE=true BACKUP_PASSPHRASE=demo-backup-passphrase python app.py
```

### Why those two environment variables are not optional on a first run

| Variable | Without it | Why |
| --- | --- | --- |
| `DEMO_MODE=true` | **You cannot log in at all.** | The OTP is deliberately not returned by `/api/login`. It is normally emailed, but SMTP is unconfigured out of the box, so there is no way to obtain a code — and the authenticator-enrolment endpoint needs you to already be logged in. Demo mode puts the code back in the login response and on the OTP screen. |
| `BACKUP_PASSPHRASE=...` | Backup Center returns **HTTP 400**. | The backup key is derived from a passphrase rather than stored on disk, so there is nothing to derive it from until you supply one. This is the intended behaviour, not a fault — see **Backup passphrase** below. |

Both are security controls behaving correctly. They are relaxed for the demo
deliberately and the reasoning for each is documented in its own section.

### Walkthrough after both processes are running

1. Open `https://localhost:5173` and accept the certificate warning.
2. Open `https://localhost:5000/api/session` once and accept that warning too.
   The API is a separate origin; if you skip this, every request from the SPA
   fails silently.
3. **Register two customer accounts** (for example `alice` and `bob`). Each is
   created with an opening balance of LKR 150,000. Do this before trying a
   transfer: the seeded `admin` and `security` accounts are operator logins
   with a zero balance and cannot send money, and on a fresh database there is
   no one to send it to.
4. Sign in as `alice`. The OTP is shown on the login screen in demo mode.
5. **Transfer** to `bob`'s 12-digit account number, shown on his dashboard.
   Watch the cryptographic pipeline run.
6. **Transaction History** shows the record with its signature re-verified on
   read.
7. Sign in as `security` / `Security@123` (staff portal) for the Security
   Center and **Backup Center**.

## Running the app (HTTPS on both processes)

**HTTPS is the default.** Both processes read the same `cert.pem` / `key.pem`
pair from the project root, so the browser, the SPA and the API are all on TLS.
This is not optional decoration: the session cookie is `Secure` + `SameSite=None`,
and a browser refuses to send a `Secure` cookie from an `http://` page, so a
half-TLS stack silently breaks authentication.

### 0. Create the TLS certificate (once)

```bash
pip install -r requirements.txt
python scripts/generate_cert.py
```

This writes `cert.pem` and `key.pem` to the project root: RSA-2048, SHA-256
signature, 365-day validity, and a `subjectAltName` covering `localhost`,
`127.0.0.1` and `::1`. The SAN matters — browsers have ignored the legacy
`commonName` field since 2017, so a certificate without it is rejected outright.

### 1. Backend (Flask API) — `SecureBankPrototype/`

```bash
python app.py
```

The API runs on `https://127.0.0.1:5000`. All routes are under `/api/*` and
return JSON. It binds to loopback only; set `HOST=0.0.0.0` to expose it on a
network you control. If `cert.pem`/`key.pem` are absent it falls back to plain
HTTP and the session cookie will not survive a cross-origin request.

### 2. Frontend (React SPA) — `SecureBankPrototype/frontend/`

```bash
cd frontend
npm install
npm run dev
```

The SPA runs on `https://localhost:5173` and talks to the API at
`https://localhost:5000/api` (override with `VITE_API_BASE` in `frontend/.env`).
`vite.config.js` picks up the same certificate pair automatically and warns on
the console if it is missing.

> The certificate is self-signed, so the browser shows a "not private" warning
> the first time. Accept it **once per origin** — port 5173 and port 5000 are two
> separate origins, and the API's warning must be accepted too or every `fetch`
> from the SPA fails. Visit `https://localhost:5000/api/session` directly once to
> clear it.

## Default accounts

Two operator accounts are auto-created when the Flask app first starts.

| Username | Password | Portal | Role |
| --- | --- | --- | --- |
| `admin` | `Admin@123` | Staff | Admin panel, all data |
| `security` | `Security@123` | Staff | Security Center, Backup Center |

> **Expected behaviour, not a bug:** both ship with a password published in
> this README, so both are flagged `must_change_password`. After the OTP step
> the SPA sends them to **Settings** with a red banner instead of the
> dashboard, and keeps doing so until the password is changed. That is the
> forced-rotation control working. Change the password, or carry on using the
> rest of the interface from the sidebar — nothing is blocked.

> **These are not customer accounts.** Both have a zero balance and cannot
> make transfers. Register a customer account (opening balance LKR 150,000) for
> the banking journey.

## Two-Factor Authentication (enrolling an authenticator app)

Each account is issued its own TOTP secret at registration. By default the API
does **not** reveal the current one-time code — returning it in the login
response would hand the second factor to whoever just supplied the password,
which makes MFA decorative. Instead, enrol the secret into a real authenticator
app.

### Enrol in Google Authenticator / Microsoft Authenticator

1. Log in and complete the OTP step once (see demo mode below if you are
   setting the account up for the first time).
2. Call the authenticated enrolment endpoint:

   ```bash
   curl -k --cookie cookies.txt https://127.0.0.1:5000/api/profile/otp-uri
   ```

   It returns the `otpauth://` provisioning URI plus the raw base32 secret:

   ```json
   {
     "ok": true,
     "otpUri": "otpauth://totp/SecureBankPrototype:alice?secret=JBSWY...&issuer=SecureBankPrototype",
     "secret": "JBSWY3DPEHPK3PXP",
     "issuer": "SecureBankPrototype",
     "account": "alice",
     "algorithm": "TOTP / SHA-1 / 6 digits / 30 second period"
   }
   ```

3. Add it to the app:
   - **Google Authenticator** — *+* → *Enter a setup key* → paste the `account`
     as the account name and the `secret` as the key, key type *Time based*.
   - **Microsoft Authenticator** — *+* → *Other account* → *Enter code manually*
     → paste the `account` and `secret`.
   - Or render `otpUri` as a QR code and scan it, which carries the same data.

4. From then on, the 6-digit code shown in the app is what `/api/otp/verify`
   expects. Codes rotate every 30 seconds; the API accepts one step of clock
   drift either side.

The endpoint only ever returns the secret belonging to the currently
authenticated user, and each request is written to `logs/security.log` as an
`OTP_ENROLMENT_ISSUED` event.

### Demo mode

For a live demonstration where installing an authenticator app is impractical,
set `DEMO_MODE=true` before starting the API:

```bash
# Windows PowerShell
$env:DEMO_MODE = "true"; python app.py

# bash
DEMO_MODE=true python app.py
```

With demo mode on, `/api/login` adds a `demoOtp` field to its response and the
React OTP screen displays it. Leave it unset (the default, `False`) for any
run that is meant to represent the secure configuration.

## Generate Self-Signed TLS Certificate

Use the bundled script — it sets the `subjectAltName` that browsers require:

```bash
python scripts/generate_cert.py            # writes ./cert.pem and ./key.pem
python scripts/generate_cert.py --force    # replace an existing pair
python scripts/generate_cert.py --days 30  # shorter validity
```

The equivalent with OpenSSL, if you prefer, needs the SAN passed explicitly:

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

A bare `openssl req -x509 ...` with no `-addext` produces a certificate modern
browsers reject, because the legacy `commonName` field is no longer consulted.

## Backup passphrase

The database backup is encrypted with a key derived from an operator passphrase
using scrypt, with a fresh random salt stored beside the backup. **The key
itself is never written to disk** - previously it sat in
`backups/bank_backup.key` next to the ciphertext, so anyone who copied the
backup directory got both halves.

Supply the passphrase in either of two ways:

```bash
# Windows PowerShell - applies to every backup this process runs
$env:BACKUP_PASSPHRASE = "choose-a-long-passphrase"
python app.py
```

or per request, as a `passphrase` field on `POST /api/security/backup` and
`POST /api/security/backup/verify`.

> **If you press "Run Backup" without setting this, you get HTTP 400 and the
> message "A backup passphrase is required." That is correct behaviour, not a
> defect.** The encryption key is derived from the passphrase on demand and is
> never written to disk, so with no passphrase there is genuinely nothing to
> derive a key from. The previous build wrote the key to
> `backups/bank_backup.key` beside the ciphertext, which meant copying the
> backup directory copied the key as well; removing that file is the fix, and
> this prompt is its visible consequence. Start the API with
> `BACKUP_PASSPHRASE` set, as in the Quick start above, and the Backup Center
> works normally.
>
> Verifying a backup with the *wrong* passphrase derives the wrong key and fails
> the AES-GCM tag check, returning HTTP 422 - the same path a corrupted backup
> file takes.

## Verification scripts

Two scripts in `scripts/` demonstrate the controls end to end against a running
API. Start `python app.py` first, then run them from the project root.

| Script | What it proves |
| --- | --- |
| `python scripts/test_race.py` | Fires six concurrent transfers of 900 from a balance of 1000. Exactly one is accepted; the other five get HTTP 400. Confirms the double-spend race is closed and the balance is exact. |
| `python scripts/test_tamper.py` | Writes a real transaction, then edits the encrypted row directly in SQLite and confirms `GET /api/transactions` reports it as `TAMPERED`. Runs two attacks: a byte flip (caught by AES-GCM) and a re-encryption with the correct AES key (caught only by the RSA signature). |

## Protocol Security

The coursework brief requires protocol-level security across three categories.
All three are implemented, and each one logs the parameters it actually
negotiated to `logs/security.log` rather than asserting them.

| Category | Protocol | Port | Security parameters |
| --- | --- | --- | --- |
| Web content transfer | HTTPS (HTTP/1.1 over TLS) | 5000 (API), 5173 (SPA) | TLS 1.3, `TLS_AES_256_GCM_SHA384`, RSA-2048 / SHA-256 self-signed certificate with SAN for `localhost`, `127.0.0.1`, `::1` |
| Electronic mail | SMTP with STARTTLS (RFC 3207) | 587 (submission) | TLS negotiated by `ssl.create_default_context()` — certificate chain + hostname verified, TLS 1.2 minimum; AUTH sent only after the upgrade |
| File transfer | SFTP (SSH-2 subsystem) | 22 | Public-key authentication, mandatory `known_hosts` verification via `paramiko.RejectPolicy`, e.g. `aes128-ctr` with `hmac-sha2-256` |

### 1. Web content transfer — HTTPS

Both processes serve TLS (see *Running the app* above). Every API response also
carries a set of browser-enforced protocol controls, applied centrally by the
`@app.after_request` hook in `app.py`:

| Header | Value | Attack it addresses |
| --- | --- | --- |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | Protocol downgrade / SSL stripping. Sent only over an already-secure connection, since HSTS on a plaintext response is ignored by design. |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` | XSS and injected-content execution. The origin serves only JSON and one PDF, so nothing needs to load or run. |
| `X-Content-Type-Options` | `nosniff` | MIME sniffing — stops a browser executing a JSON response as script. |
| `X-Frame-Options` | `DENY` | Clickjacking. |
| `Referrer-Policy` | `no-referrer` | Leaking account numbers and endpoint paths to third-party sites. |

Verify them directly:

```bash
curl -k -D - -o /dev/null https://127.0.0.1:5000/api/session
```

### 2. Electronic mail — SMTP over STARTTLS

`security/mailer.py` connects to the mail submission port, issues `STARTTLS` to
upgrade the connection, and only then sends `AUTH` and the message body — so
neither the mailbox password nor the message ever crosses the network in the
clear. The TLS session is built from `ssl.create_default_context()`, which
validates the server's certificate chain and hostname and refuses obsolete
protocol versions and weak ciphers.

It is used for two things:

- **The login OTP.** The one-time password is emailed to the address on file
  instead of being returned in the `/api/login` response. This is what makes the
  second factor an actual second factor.
- **Transfer confirmations.** Sent after a successful transfer, as step 8 of the
  transfer security pipeline.

Configure it entirely from the environment — no credential is ever committed:

```bash
# Windows PowerShell
$env:SMTP_HOST = "smtp.gmail.com"
$env:SMTP_PORT = "587"
$env:SMTP_USER = "you@gmail.com"
$env:SMTP_PASSWORD = "your-app-password"
$env:SMTP_FROM = "you@gmail.com"
python app.py
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `SMTP_HOST` | *(empty)* | Mail server hostname. Empty disables mail. |
| `SMTP_PORT` | `587` | Submission port used with STARTTLS. |
| `SMTP_USER` | *(empty)* | AUTH username. |
| `SMTP_PASSWORD` | *(empty)* | AUTH password / app password. |
| `SMTP_FROM` | *(empty)* | Envelope and header sender address. |
| `SMTP_TIMEOUT` | `10` | Socket timeout, so an unreachable host cannot hang a login. |

**Evidence for the report.** The negotiated TLS version and cipher suite are read
off the live socket after the handshake and written to `logs/security.log`:

```
[2026-08-27 22:48:16] MAIL_SENT | user=customer@example.com | subject='SecureBank one-time password' server=smtp.example.com:587 tls=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384 (256-bit, TLSv1.3)
[2026-08-27 22:48:16] OTP_DISPATCHED | user=alice | channel=email delivered=True tls=TLSv1.3
```

The same values come back in the `/api/login` response under `otpDelivery`, and in
the `/api/transfer` response under `mailConfirmation`, so they can be screenshotted
from the browser's network tab as well as from the log.

**If SMTP is not configured** the mailer logs `MAIL_SKIPPED` and returns a
"not sent" result instead of raising — the app still runs. In that case get the
OTP from an enrolled authenticator app (see *Two-Factor Authentication* above) or
start the API with `DEMO_MODE=true`.

### 3. File transfer — SFTP over SSH-2

`security/sftp_backup.py` pushes the encrypted database backup to an offsite
server over SFTP, the file-transfer subsystem of SSH. Plain FTP is never used: it
would carry both the credentials and the file in cleartext.

Two properties make this real rather than decorative:

- **Host key verification is mandatory.** The client loads a `known_hosts` file
  and installs `paramiko.RejectPolicy`. `AutoAddPolicy` is deliberately *not*
  used — trusting whatever key answers on the port would hand the backup to any
  machine-in-the-middle and defeat the point of using SSH. A missing
  `known_hosts`, an unpinned server, or a changed server key all abort the
  transfer.
- **Public-key authentication only.** `allow_agent` and `look_for_keys` are off,
  so the configured key file is the only credential attempted and no password
  ever crosses the link.

Only the already AES-256-GCM-encrypted artefact is uploaded, so the plaintext
database never leaves the host even if the remote server is later compromised.

Pin the server's key first, then configure:

```bash
ssh-keyscan -p 22 backup.example.com > security/known_hosts

# Windows PowerShell
$env:SFTP_HOST = "backup.example.com"
$env:SFTP_USER = "backupbot"
$env:SFTP_KEY_PATH = "C:\\Users\\you\\.ssh\\id_rsa"
python app.py
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `SFTP_HOST` | *(empty)* | Offsite server hostname. Empty disables upload. |
| `SFTP_PORT` | `22` | SSH port. |
| `SFTP_USER` | *(empty)* | SSH username. |
| `SFTP_KEY_PATH` | *(empty)* | Private key file for public-key authentication. |
| `SFTP_KNOWN_HOSTS` | `security/known_hosts` | Pinned server public keys. Must exist. |
| `SFTP_REMOTE_DIR` | `securebank-backups` | Remote directory, created if absent. |
| `SFTP_TIMEOUT` | `15` | Connection timeout in seconds. |

The upload runs as **step 6, "Upload to offsite SFTP"**, of the existing backup
pipeline, so it appears in the Backup Center UI next to the encryption and
integrity steps. The full result is also returned under `offsiteTransfer`.

**Evidence for the report.** The negotiated SSH cipher and MAC, and the verified
host key type, are logged:

```
[...] SFTP_UPLOAD_SUCCESS | user=system | remote=backup.example.com:securebank-backups/bank_backup.db.enc hostKey=ssh-rsa cipher=aes128-ctr (out) / aes128-ctr (in) mac=hmac-sha2-256 (out) / hmac-sha2-256 (in)
```

Rejections are logged just as loudly, which is the more interesting screenshot:

```
[...] SFTP_REJECTED           | user=system | Refusing to connect: known_hosts file 'security/known_hosts' not found. ...
[...] SFTP_FAILED             | user=system | SSH/SFTP transfer refused: Server '[backup.example.com]:22' not found in known_hosts
[...] SFTP_HOST_KEY_MISMATCH  | user=system | Host key mismatch for backup.example.com: the server presented a key that does not match security/known_hosts. Upload aborted.
```

If SFTP is not configured, or `paramiko` is not installed, the step reports
`skipped` and the backup still completes locally.

## Security Notes

This section maps directly onto the three CW2 marking criteria. Each row names the
control, the specific algorithm or protocol with its parameters, and the file and
function where it is implemented.

### Algorithm level (40%)

| Control | Algorithm and parameters | Implemented in |
| --- | --- | --- |
| Password storage | scrypt (werkzeug `generate_password_hash`), N=32768, r=8, p=1, per-user random salt | `security/hashing.py` → `password_hash()`, `verify_password()` |
| Rejection of weak hashes | Any digest without a `scrypt:` / `pbkdf2:` prefix is refused; there is no unsalted SHA-256 comparison path | `security/hashing.py` → `verify_password()` |
| Legacy hash migration | Unsalted SHA-256 digests are re-hashed under scrypt at startup, then replaced by a direct scrypt hash on the owner's next successful login | `security/hashing.py` → `wrap_legacy_sha256()`, `needs_rehash()`; `app.py` → `migrate_legacy_password_hashes()` |
| Password complexity | Minimum 8 characters with upper, lower, digit and symbol | `security/hashing.py` → `validate_password_complexity()` |
| Payload and manifest hashing | SHA-256 | `security/hashing.py` → `sha256_hash()`, `sha256_hash_bytes()` |
| Transaction field encryption | AES-256-GCM, fresh 256-bit key per transfer, random 128-bit nonce and 128-bit authentication tag per record | `security/aes.py` → `aes_encrypt()`, `aes_decrypt()`; `app.py` → `api_transfer()` |
| Database backup encryption | AES-256-GCM over the whole SQLite file | `security/aes.py` → `aes_encrypt_bytes()`, `aes_decrypt_bytes()`; `app.py` → `api_backup_database()` |
| Backup key derivation | scrypt, N=16384, r=8, p=1, 16-byte random salt, 256-bit output; the key is never written to disk | `app.py` → `derive_backup_key()` |
| AES key wrapping | RSA-2048 with OAEP padding (see the limitation on key ownership below) | `security/rsa.py` → `rsa_encrypt()`, `rsa_decrypt()` |
| Transaction signing | RSASSA-PSS over SHA-256 with MGF1 (RFC 8017 §8.1), RSA-2048 | `security/digital_signature.py` → `sign_data()` |
| Signature verification on read | PSS attempted first; RSASSA-PKCS#1 v1.5 accepted only for records predating the upgrade. Failure returns `TAMPERED` and logs `SIGNATURE_INVALID` | `security/digital_signature.py` → `verify_signature_detailed()`; `app.py` → `verify_transaction_row()`, `api_transaction_history()` |
| Second factor | TOTP (RFC 6238), SHA-1, 6 digits, 30-second step, ±1 step drift tolerance | `security/otp.py` → `current_otp()`, `verify_otp()` |
| Authenticator enrolment | `otpauth://` provisioning URI so the code is generated on the user's device | `security/otp.py` → `provisioning_uri()`; `app.py` → `api_profile_otp_uri()` |
| Exact monetary arithmetic | `decimal.Decimal` quantized to 2 places with `ROUND_HALF_UP`, stored and compared as integer minor units (cents) | `app.py` → `parse_money()`, `to_minor()`, `from_minor()`, `money_json()` |

### Protocol level (30%)

| Control | Protocol and parameters | Implemented in |
| --- | --- | --- |
| Web content transfer | HTTPS (HTTP/1.1 over TLS 1.3, `TLS_AES_256_GCM_SHA384`); API on port 5000, SPA on port 5173 | `app.py` → `__main__`; `security/certificate.py` → `ssl_context_if_available()`; `frontend/vite.config.js` |
| TLS certificate | RSA-2048, SHA-256 signature, 365-day validity, `subjectAltName` for `localhost`, `127.0.0.1`, `::1`, EKU `serverAuth` | `scripts/generate_cert.py` → `build_certificate()` |
| Transport and content headers | `Strict-Transport-Security: max-age=31536000; includeSubDomains` (secure connections only), `Content-Security-Policy: default-src 'none'`, `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer` | `app.py` → `apply_security_headers()` |
| Secure electronic mail | SMTP with STARTTLS (RFC 3207) on submission port 587; TLS from `ssl.create_default_context()`, so the certificate chain and hostname are verified and TLS below 1.2 is refused; AUTH is sent only after the upgrade | `security/mailer.py` → `send_secure_email()` |
| Secure file transfer | SFTP as an SSH-2 subsystem on port 22; public-key authentication only (`allow_agent=False`, `look_for_keys=False`); mandatory `known_hosts` verification via `paramiko.RejectPolicy`; negotiated cipher and MAC logged (e.g. `aes128-ctr`, `hmac-sha2-256`) | `security/sftp_backup.py` → `upload_backup()` |
| Session cookie | `HttpOnly`, `Secure`, `SameSite=None`, 20-minute idle lifetime | `config.py` → `Config`; `app.py` → `touch_session()` |
| Cross-origin control | Single allowed origin (`https://localhost:5173`) with credentials; `X-CSRFToken` permitted in preflight | `app.py` → `CORS(...)` |
| CSRF protection | Session-bound token echoed in an `X-CSRFToken` header on every POST/PUT/PATCH/DELETE; rejections logged as `CSRF_REJECTED` | `app.py` → `CSRFProtect`, `api_csrf_token()`, `handle_csrf_error()`; `frontend/src/api.js` → `getCsrfToken()` |
| Secure report transfer | PDF security report served over the same authenticated HTTPS channel | `app.py` → `api_security_report_download()` |
| Not implemented | IMAP and FTP/FTPS — the prototype has no mail-retrieval workflow, and FTP is deliberately excluded in favour of SFTP | — |

### System level (30%)

| Control | Mechanism and parameters | Implemented in |
| --- | --- | --- |
| Encrypted system backup | AES-256-GCM snapshot, SHA-256 manifest, and an in-memory decrypt-and-rehash verification before the run is reported as successful | `app.py` → `api_backup_database()`, `api_verify_backup()` |
| Offsite backup transfer | Only the already-encrypted artefact is pushed over SFTP, so plaintext never leaves the host | `security/sftp_backup.py` → `upload_backup()` |
| Session signing key | 256-bit random key from `SECRET_KEY`, otherwise generated on first run and persisted to the gitignored `.secret_key`; no hardcoded default | `config.py` → `load_secret_key()` |
| Role-based access control | `customer`, `security` and `admin` roles gate the banking and security endpoints; a portal check stops staff logging in through the customer form | `app.py` → `role_required()`, `admin_required()`, `PORTAL_ROLES` |
| Forced default-password change | `must_change_password` flag set on the seeded `admin` and `security` accounts; the SPA routes those users to Settings until they change it | `app.py` → `init_db()`, `api_otp_verify()`, `api_profile_change_password()`; `frontend/src/pages/Otp.jsx`, `frontend/src/pages/Settings.jsx` |
| Brute-force lockout | 5 failed attempts trigger a 10-minute lock, shared by the password and OTP stages so the second factor cannot be ground down independently | `app.py` → `user_locked()`, `unlock_if_expired()`, `api_login()`, `api_otp_verify()` |
| Concurrency / double-spend control | `BEGIN IMMEDIATE` plus a single conditional `UPDATE … WHERE balance >= amount`, so the sufficiency check and the debit cannot be separated | `app.py` → `api_transfer()`, `api_wallet_topup()`; proof in `scripts/test_race.py` |
| Firewall monitoring | Reads Windows Defender Firewall profile and rule status through PowerShell; read-only, it never changes rules | `security/firewall_monitor.py` → `firewall_status_payload()`, `get_firewall_profiles()` |
| IDS-style event monitoring | Append-only security log of login, OTP, transfer, signature, CSRF, mail, SFTP and backup events, surfaced in the Security Operations Centre | `app.py` → `setup_logging()`, `log_event()`, `security_timeline_entries()` |
| Network exposure control | Binds `127.0.0.1` by default; the Werkzeug debugger is enabled only by `FLASK_DEBUG` and prints a warning to stderr when on | `app.py` → `__main__` |
| Audit evidence | Downloadable PDF security report, log viewer, database viewer and attack-simulation lab | `app.py` → `security_report_payload()`, `build_security_report_pdf()`, `run_attack_simulation()` |

### Prototype limitations

- **The RSA key wrapping demonstrates the mechanism rather than providing real
  protection.** Each transfer's AES key is wrapped with the server's *own*
  RSA-2048 public key, and the matching private key sits on the same host in
  `security/rsa_private.pem`. Anything that can read the database can also read
  that key file, so the wrapping does not keep the transaction fields secret
  from an attacker who has already reached the server - it shows the
  hybrid-encryption construction working end to end. A production design would
  wrap the data key under a key the application server cannot export: a KMS or
  HSM key where the unwrap is a remote, audited, rate-limited operation, or a
  recipient-held public key so that only the intended party can unwrap. The
  private key would never exist as a readable file next to the data it protects.
- **`WTF_CSRF_SSL_STRICT` is disabled** (`config.py`). With it enabled,
  Flask-WTF additionally requires, on any HTTPS request, that the `Referer`
  header match the API's own origin. The SPA is served from
  `https://localhost:5173` while the API answers on `https://localhost:5000`, so
  that check can never pass here and would reject every legitimate request. The
  protection that actually operates is the session-bound CSRF token: a
  cross-origin attacker's page can cause the browser to attach our session
  cookie, but the same-origin policy prevents it from reading the token it would
  have to echo back, and `CORS_ORIGIN` restricts which origin may read our
  responses at all. On a deployment where the SPA and API share one origin, this
  setting should be turned back on.
- The SQLite database is not encrypted as a whole; selected transaction fields and backup snapshots are encrypted.
- The backup passphrase is supplied by the operator per run or via an environment
  variable. A production system would hold the derived key in an HSM or a managed
  key vault rather than deriving it from something a person types.
- The legacy `current_balance` / `wallet_balance` REAL columns remain in the
  schema so an existing database still opens, but nothing reads them after the
  one-time backfill; `current_balance_minor` / `wallet_balance_minor` are the
  source of truth.
- The TLS certificate is self-signed. Production deployments need a certificate from a trusted CA so that clients validate the chain instead of clicking through a warning.
- The OTP is emailed as message text. A production bank would use a push-approval or hardware factor; the enrolled-authenticator path (`GET /api/profile/otp-uri`) is the stronger option already available here, since the code is then generated on the device and never transmitted.
- Windows Firewall integration, IDS monitoring, HTTPS certificates, and backups depend on local operating-system configuration and permissions.
- This prototype does not connect to real banking, mail, payment, or external file-transfer services.
