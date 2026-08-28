# CW2 — What Changed, and How to Test It

**Branch:** `master` (merged from `ui-polish`)
**Commit:** `4995fc9` — 38 files, +4470 / −2005

---

## Part 1 — Before and after, piece by piece

Grouped by marking criterion, so this doubles as material for your submission notes.

### Algorithm level (40%)

| # | Before | After |
|---|---|---|
| 1 | Passwords: `verify_password()` fell back to **unsalted SHA-256** for any hash without a `scrypt:`/`pbkdf2:` prefix | Fallback removed entirely. Unrecognised hashes are rejected. Legacy rows re-hashed under scrypt at startup, upgraded to a direct scrypt hash on next login |
| 2 | Signatures: **RSASSA-PKCS#1 v1.5** | **RSASSA-PSS** over SHA-256 with MGF1. PKCS#1 v1.5 retained on the *verify* path only, so old demo records still read |
| 3 | `/api/transactions` returned the hardcoded string `"signature": "Verified (RSA-SHA256)"` — **nothing was ever verified** | Every row's signed payload is reconstructed and actually verified. Returns real `signatureValid` / `VERIFIED` / `TAMPERED`, logs `SIGNATURE_INVALID`, shows a warning badge |
| 4 | Money as Python `float` — balances would drift | `decimal.Decimal` quantized to 2 places, stored and compared as **integer minor units (cents)**. New `current_balance_minor` / `wallet_balance_minor` columns, backfilled |
| 5 | Backup key written to `backups/bank_backup.key`, **beside the ciphertext** | Key derived from an operator passphrase via **scrypt (N=16384, r=8, p=1)** with a random salt. Only the salt is stored; the key never touches disk. Old key file deleted on next backup |
| 6 | AES-256-GCM already in place (good) | Unchanged, but every stale "AES-256-CBC" label in code and UI corrected |

### Protocol level (30%) — the section that was nearly empty

| # | Before | After |
|---|---|---|
| 7 | **No secure mail.** README declared SMTP/IMAP out of scope | `security/mailer.py` — SMTP + **STARTTLS on 587**, TLS from `ssl.create_default_context()` (chain + hostname verified). Delivers the login OTP and transfer confirmations. Negotiated TLS version and cipher logged |
| 8 | **No file transfer.** README declared FTP/SFTP out of scope | `security/sftp_backup.py` — **SFTP over SSH-2**, public-key auth only, **mandatory `known_hosts` verification via `RejectPolicy`** (not `AutoAddPolicy`). Added as step 7 of the backup pipeline |
| 9 | HTTPS optional; README told you to **run over plain HTTP** | HTTPS is the documented default on **both** processes. `scripts/generate_cert.py` mints a SAN-bearing cert; `vite.config.js` picks up the same pair |
| 10 | **No security headers** | `@app.after_request` sets HSTS, CSP, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` |
| 11 | **No CSRF protection** with `SameSite=None` cookies | Flask-WTF `CSRFProtect` on every POST/PUT/PATCH/DELETE. Token from `GET /api/csrf-token`, echoed as `X-CSRFToken`. Rejections logged as `CSRF_REJECTED` |

### System level (30%)

| # | Before | After |
|---|---|---|
| 12 | **Double-spend race** — balance check and debit were separate statements. Reproduced: 6 concurrent 900-transfers from a 1000 balance all succeeded, LKR 4,500 created from nothing | `BEGIN IMMEDIATE` + a single conditional `UPDATE … WHERE col >= ?`. Now 1 accepted, 5 rejected. Proof in `scripts/test_race.py` |
| 13 | `debug=True` on `host="0.0.0.0"` — Werkzeug console exposed to the network | Binds `127.0.0.1`; debug driven by `FLASK_DEBUG` alone, with a stderr warning. `DEMO_MODE` no longer enables it |
| 14 | `GET /` returned **`"admin_password": "Admin@123"`** unauthenticated | Liveness check only: `ok`, `message`, `api_base` |
| 15 | `SECRET_KEY` defaulted to `"dev-secret-change-me"` — forgeable session cookies | Env var, else a random 256-bit key generated on first run and persisted to gitignored `.secret_key`. No default |
| 16 | Seeded `admin`/`security` on published passwords, no prompt | `must_change_password` flag; SPA routes those accounts to Settings with a banner until changed |
| 17 | `POST /api/profile/password` raised **NameError → 500 on every attempt** (`verify_sha256` called but never imported) | Uses `verify_password`. Dead `verify_sha256` removed from `hashing.py` |
| 18 | No OTP throttle — 30 wrong codes all returned 401 | Wrong codes increment `failed_attempts`, lock at 5 for 10 minutes, shared with the password stage |

### Documentation, identity, interface

| # | Before | After |
|---|---|---|
| 19 | README claimed SHA-256 passwords and AES-CBC — both false. Stale labels in 11 code sites and 5 UI strings | All corrected. `SCHEME_PSS` imported so display labels can't drift from the signing code again |
| 20 | Security Notes as prose bullets | Three tables mapped to **Algorithm 40% / Protocol 30% / System 30%**, each row giving control → algorithm with parameters → file and function |
| 21 | Limitations vague | States plainly that RSA wrapping uses the server's own keypair (demonstration, not protection), and why `WTF_CSRF_SSL_STRICT` is off |
| 22 | Setup instructions **did not work from a clean clone** — no route to a valid OTP existed | Quick start with both env vars, 7-step walkthrough, both default accounts tabulated with expected behaviours |
| 23 | No favicon identity; sage-green UI vs navy mark | Shield favicon + PNG fallback + `theme.css` brand tokens. 20 ad-hoc font sizes → 8-step scale; 20+ padding values → 8-step scale |
| 24 | **Zero** `:focus-visible` rules, one unreplaced `outline: none`, no `prefers-reduced-motion`, `--ink-soft` at 3.53:1 (fails AA) | Focus ring on everything, full reduced-motion block, all text AA-verified against its actual background |
| 25 | Red meant "sent", "pending" and "failed" simultaneously | Red reserved for `.alert-danger` and `.badge-alarm` only. Direction is neutral, degraded states amber |
| 26 | No tests | `test_race.py` and `test_tamper.py`, both passing |
| 27 | `CW1.jpg` + three `.bak-green` files in the repo | Deleted |

---

## Part 2 — Full system test workflow

Run this end to end. Roughly 40 minutes including screenshots. Capture evidence as you go — the screenshots are worth marks.

### Setup

```powershell
cd "D:\Security 3rd Year\SecureBankPrototype-CW2"

# Terminal 1 — API
$env:DEMO_MODE = "true"
$env:BACKUP_PASSPHRASE = "coursework-demo-passphrase"
python app.py

# Terminal 2 — SPA
cd frontend
npm run dev
```

Open `https://localhost:5173`. If you get a certificate warning, also visit `https://localhost:5000/api/session` once and accept there — they are separate origins.

---

### A. Authentication (algorithm + system)

| Step | Do | Expect | Screenshot? |
|---|---|---|---|
| A1 | Register `alice` / `Alice@1234` | Success. Response `security.algorithm` = **scrypt** | — |
| A2 | Register `bob` / `Bob@12345` | Success. Note bob's 12-digit account number | — |
| A3 | Log in as alice with the **wrong** password 5 times | Locks on the 5th: "Account locked" | ✔ |
| A4 | Wait or reset, log in correctly | OTP screen. Code shown (DEMO_MODE) | — |
| A5 | Enter a **wrong** OTP 5 times | 401 ×4, then **403 lockout** — proves the OTP throttle | ✔ |
| A6 | Reset and log in properly | Dashboard, LKR 150,000.00 | — |

Reset a lock: `python -c "import sqlite3; d=sqlite3.connect('database/bank.db'); d.execute(\"UPDATE users SET failed_attempts=0, locked_until=NULL\"); d.commit()"`

**A7 — forced password change.** Log in as `admin` / `Admin@123` on the staff portal. You should land on **Settings with a red banner**, not the dashboard. Change the password, confirm the banner clears. ✔

**A8 — password change works at all.** This returned 500 on every attempt before. Confirm wrong-current → 401, mismatch → 400, weak → 400, valid → 200.

---

### B. Transfer and the pipeline (the signature demo)

| Step | Do | Expect | Screenshot? |
|---|---|---|---|
| B1 | As alice, transfer 250.00 to bob's account, source Card | Success | — |
| B2 | Watch the **Pipeline Rail** | 8 stages on a navy→teal gradient: plaintext, SHA-256, AES-256-GCM, RSA-2048-OAEP, **RSASSA-PSS**, TLS, storage, mail confirmation | ✔ **key shot** |
| B3 | Check the balance | Exactly 149,750.00 | — |
| B4 | Transfer 999,999 | 400 with a **remedy**: "Lower the amount, or top up the wallet…" | ✔ |
| B5 | Transfer to alice's own number | 400 "Enter the recipient's account number instead" | — |
| B6 | Transfer `abc` | 400 "Enter an amount such as 250.00…" | — |

**B7 — exact money.** Three transfers of 0.10 then one of 0.01. Balance must drop by exactly 0.31, no drift.

---

### C. Integrity — the strongest demo you have

| Step | Do | Expect | Screenshot? |
|---|---|---|---|
| C1 | Open Transaction History | Green **Verified** badges; direction is neutral, not red | ✔ |
| C2 | Click "View security" | Real scheme: `RSASSA-PSS (SHA-256, MGF1)` | ✔ |
| C3 | Run `python scripts/test_tamper.py` | 4/4 PASS | ✔ |
| C4 | Reload Transaction History mid-tamper | Red banner, tinted row, **TAMPERED** chip, amount reads "Unverifiable" | ✔ **key shot** |
| C5 | `grep SIGNATURE_INVALID logs/security.log` | Entries present | ✔ |

C3's Scenario B is the one to explain: the attacker re-encrypts a different amount with the *correct* AES key, so AES-GCM is satisfied — only the RSA signature catches it.

---

### D. Concurrency

```powershell
python scripts\test_race.py
```

6 concurrent transfers of 900 from a 1000 balance → **1 accepted, 5 rejected**, balance exactly 100.00. Six PASS lines. ✔ **key shot**

---

### E. Protocol evidence — your weakest section on paper, so document it hard

**E1 — security headers:**
```powershell
curl.exe -k -D - -o NUL https://127.0.0.1:5000/api/session
```
Five headers present. ✔

**E2 — TLS version and cipher:**
```powershell
python -c "import ssl,socket; c=ssl._create_unverified_context(); s=c.wrap_socket(socket.create_connection(('127.0.0.1',5000)), server_hostname='localhost'); print(s.version(), s.cipher())"
```
`TLSv1.3 ('TLS_AES_256_GCM_SHA384', …)` ✔

**E3 — SMTP+STARTTLS.** With SMTP configured, log in and check the log:
```
MAIL_SENT | … tls=TLSv1.3 cipher=TLS_AES_256_GCM_SHA384
```
✔ If you have no mail server, say so in your notes — the code path is verified and the mechanism is documented.

**E4 — SFTP host-key verification.** The *rejection* is the better screenshot. With `SFTP_HOST` set to anything and no `known_hosts`, run a backup:
```
SFTP_REJECTED | Refusing to connect: known_hosts file not found
```
That proves you did **not** use `AutoAddPolicy`. ✔

**E5 — CSRF:**
```powershell
curl.exe -k -X POST https://127.0.0.1:5000/api/login -H "Content-Type: application/json" -d "{\"username\":\"alice\",\"password\":\"Alice@1234\",\"portal\":\"customer\"}"
```
400 `"csrf": true`. The SPA works because it sends the token; a forged cross-site request does not. ✔

---

### F. Security Center and backup

| Step | Do | Expect | Screenshot? |
|---|---|---|---|
| F1 | Open Security Center as `security` / `Security@123` | Status grid readable at a glance — fill + glyph, not colour alone | ✔ |
| F2 | Run each of the 6 attack simulations | All blocked. Tampered-transaction and replay are the interesting ones | ✔ |
| F3 | Backup Center → Run Backup | 7 steps incl. **Key Derivation (scrypt)** and **Upload to offsite SFTP** | ✔ |
| F4 | Check `backups/` | `.db.enc`, `.salt`, `.sha256` — **no `.key` file** | ✔ |
| F5 | Verify Backup | 200, hashMatch true | — |
| F6 | Restart the API with a **different** `BACKUP_PASSPHRASE`, verify again | **422** — wrong key fails the GCM tag | ✔ |
| F7 | Download the PDF security report | Opens, reflects real status | — |

---

### G. Interface quality floor

| Step | Do | Expect |
|---|---|---|
| G1 | F12 → device toolbar → 375px, open Transaction History | Rows **stack as labelled blocks**, no sideways scroll, no column dropped |
| G2 | Same at 375px on Transfer and Security Center | Rail runs vertically; status grid single-column |
| G3 | Tab through the login form and the transfer form | **Visible focus ring on every field and button** |
| G4 | Windows Settings → Accessibility → Visual effects → Animation effects **off**, reload, make a transfer | Rail renders complete and still — no staged reveal |
| G5 | Log out, log in with a bad password | Alert is **red** (not amber) |
| G6 | Look at the browser tab | Shield favicon visible |
| G7 | Fresh account, open Transaction History | Empty state says what to do next, with a link to Transfer |

---

### H. Final gate before packaging

1. `cd frontend && npx vite build` → passes
2. `git status` → clean
3. `securebank-local.cer` removed from tracking and from disk
4. Delete: `node_modules`, `dist`, `__pycache__`, `database/`, `logs/`, `backups/`, `.secret_key`, `cert.pem`, `key.pem`, `security/rsa_*.pem`
5. Zip, unzip to a fresh folder, `python app.py` → starts and regenerates everything
6. AI declaration attached per your module handbook

---

## The five screenshots that matter most

If time runs short, get these:

1. **Pipeline Rail** with all 8 stages (B2) — your signature element
2. **TAMPERED state** on Transaction History (C4) — proves signatures are enforced, not decorative
3. **`test_race.py` passing** (D) — proves the double-spend fix
4. **`SFTP_REJECTED`** host-key log line (E4) — proves real host-key verification
5. **Security headers** from curl (E1) — protocol-level evidence in one frame
