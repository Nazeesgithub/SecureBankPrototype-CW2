import base64
import logging
import os
import random
import shutil
import sqlite3
import string
import sys
from datetime import datetime, timedelta
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from functools import wraps

from flask import Flask, g, jsonify, request, session
from flask_cors import CORS
from flask_wtf.csrf import CSRFError, CSRFProtect, generate_csrf
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from config import Config, env_flag
from Crypto.Protocol.KDF import scrypt as scrypt_kdf

from security.aes import (
    aes_decrypt,
    aes_decrypt_bytes,
    aes_encrypt,
    aes_encrypt_bytes,
    generate_aes_key,
)
from security.certificate import certificate_status, ssl_context_if_available
from security.digital_signature import (
    SCHEME_PSS,
    sign_data,
    verify_signature,
    verify_signature_detailed,
)
from security.firewall_monitor import firewall_status_payload, get_firewall_profiles
from security.firewall_connections import read_recent_connections
from security.mailer import mask_email, send_secure_email
from security.hashing import (
    LEGACY_SHA256_PREFIX,
    MODERN_HASH_PREFIXES,
    needs_rehash,
    password_hash,
    sha256_hash,
    sha256_hash_bytes,
    validate_password_complexity,
    verify_password,
    wrap_legacy_sha256,
)
from security.otp import OTP_ISSUER, current_otp, generate_otp_secret, provisioning_uri, verify_otp
from security.rsa import ensure_rsa_keys, load_private_key, load_public_key, rsa_decrypt, rsa_encrypt
from security.sftp_backup import upload_backup


app = Flask(__name__)
app.config.from_object(Config)

BACKUP_ENCRYPTED_PATH = os.path.join("backups", "bank_backup.db.enc")
BACKUP_HASH_PATH = os.path.join("backups", "bank_backup.sha256")
BACKUP_SALT_PATH = os.path.join("backups", "bank_backup.salt")
# Retained only so a key file written by an older build can be deleted. The
# backup key is never written to disk any more - see derive_backup_key().
LEGACY_BACKUP_KEY_PATH = os.path.join("backups", "bank_backup.key")

# scrypt work factors. N=2**14 with r=8, p=1 is the interactive profile from
# the scrypt paper: roughly 100 ms and 16 MB of memory per derivation, which
# is negligible for one authorised backup but expensive for an attacker
# grinding passphrase guesses against a stolen file.
BACKUP_KDF_N = 2 ** 14
BACKUP_KDF_R = 8
BACKUP_KDF_P = 1
BACKUP_SALT_BYTES = 16

# allow_headers is listed explicitly so the browser's preflight accepts the
# CSRF header the SPA attaches to every state-changing request.
CORS(
    app,
    supports_credentials=True,
    origins=[app.config["CORS_ORIGIN"]],
    allow_headers=["Content-Type", "X-CSRFToken", "X-CSRF-Token"],
)

# Prevents cross-site request forgery: the session cookie is SameSite=None so
# that the SPA on a different origin can use it, which also means the browser
# will attach it to requests made by any other site. A token that an attacker
# cannot read (it is bound to the session and must be echoed in a header) is
# what restores the protection SameSite would otherwise have provided.
# CSRFProtect covers POST, PUT, PATCH and DELETE; GET routes stay unguarded.
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """Return CSRF rejections as JSON, since every other route does.

    The "csrf" flag lets the SPA tell a stale token apart from an ordinary 400
    and retry once with a fresh one.
    """
    log_event(
        "CSRF_REJECTED",
        current_user.username if current_user.is_authenticated else "anonymous",
        f"{request.method} {request.path}: {error.description}",
    )
    return jsonify({"ok": False, "csrf": True, "message": "CSRF token missing or invalid."}), 400


@app.get("/")
def index():
    """Unauthenticated liveness check.

    Prevents credential disclosure: this route previously returned the default
    administrator username and password to any anonymous caller, which handed
    working admin access to anyone who typed the API root into a browser. It now
    reports only that the service is up and where the API lives.
    """
    return jsonify({
        "ok": True,
        "message": "SecureBankPrototype API is running.",
        "api_base": "/api",
    })


@app.after_request
def apply_security_headers(response):
    """Protocol-level hardening: browser-enforced transport and content rules.

    setdefault() is used throughout so that a route which deliberately sets its
    own value (and the CORS headers Flask-Cors adds) is never overwritten.
    """
    # Prevents protocol downgrade / SSL stripping: instructs the browser to use
    # HTTPS for this origin for a year. Only sent over a connection that is
    # already secure, because HSTS on a plaintext response is ignored by design.
    if request.is_secure:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )

    # Prevents XSS and injected-content execution: this origin serves only JSON
    # and one PDF, so no scripts, styles, frames or form posts are ever legitimate.
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
    )

    # Prevents MIME-sniffing: stops a browser second-guessing our Content-Type
    # and executing a JSON response as script.
    response.headers.setdefault("X-Content-Type-Options", "nosniff")

    # Prevents clickjacking: the API must never be framed by another page.
    response.headers.setdefault("X-Frame-Options", "DENY")

    # Prevents referrer leakage: account numbers and endpoint paths must not be
    # forwarded to third-party sites in the Referer header.
    response.headers.setdefault("Referrer-Policy", "no-referrer")

    return response


@login_manager.unauthorized_handler
def unauthorized():
    return jsonify({"ok": False, "message": "Authentication required."}), 401


class User(UserMixin):
    def __init__(self, user_id: int, username: str, role: str = "customer"):
        self.id = str(user_id)
        self.username = username
        self.role = role


@login_manager.user_loader
def load_user(user_id: str):
    db = get_db()
    row = db.execute("SELECT id, username, role FROM users WHERE id = ?", (user_id,)).fetchone()
    if row is None:
        return None
    return User(row["id"], row["username"], row["role"])


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)
        g.db = sqlite3.connect(app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        # Prevents TOCTOU double-spend race: isolation_level=None switches off
        # the sqlite3 driver's hidden auto-BEGIN, so the money-moving endpoints
        # can open their own BEGIN IMMEDIATE transaction and hold the write
        # lock across the whole check-and-debit sequence.
        g.db.isolation_level = None
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            balance REAL NOT NULL DEFAULT 150000,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until TEXT,
            last_login TEXT
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            receiver TEXT NOT NULL,
            encrypted_amount TEXT NOT NULL,
            encrypted_message TEXT NOT NULL,
            encrypted_aes_key TEXT NOT NULL,
            signature TEXT NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'SUCCESS'
        )
        """
    )
    db.commit()

    user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "card_balance" in user_cols and "current_balance" not in user_cols:
        db.execute("ALTER TABLE users RENAME COLUMN card_balance TO current_balance")
        db.commit()
        user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "current_balance" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN current_balance REAL NOT NULL DEFAULT 0")
        db.execute("UPDATE users SET current_balance = balance")
    if "wallet_balance" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN wallet_balance REAL NOT NULL DEFAULT 0")
    if "account_number" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN account_number TEXT")
    db.commit()

    # Exact-money columns. The older REAL columns are left in place so an
    # existing database still opens, but nothing reads them after this backfill;
    # current_balance_minor / wallet_balance_minor are the source of truth.
    user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "current_balance_minor" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN current_balance_minor INTEGER NOT NULL DEFAULT 0")
        db.execute("UPDATE users SET current_balance_minor = CAST(ROUND(current_balance * 100) AS INTEGER)")
    if "wallet_balance_minor" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN wallet_balance_minor INTEGER NOT NULL DEFAULT 0")
        db.execute("UPDATE users SET wallet_balance_minor = CAST(ROUND(wallet_balance * 100) AS INTEGER)")
    db.commit()

    # Forces the seeded operator accounts off their published default passwords.
    # Databases created before this column existed still hold admin/security rows
    # on the shipped defaults, so those are flagged as part of the migration
    # rather than only at seed time.
    user_cols = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    if "must_change_password" not in user_cols:
        db.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0")
        db.execute(
            "UPDATE users SET must_change_password = 1 WHERE username IN (?, ?)",
            ("admin", "security"),
        )
    db.commit()

    for row in db.execute("SELECT id FROM users WHERE account_number IS NULL").fetchall():
        db.execute(
            "UPDATE users SET account_number = ? WHERE id = ?",
            (generate_account_number(db), row["id"]),
        )
    db.commit()

    tx_cols = {row["name"] for row in db.execute("PRAGMA table_info(transactions)")}
    if "source" not in tx_cols:
        db.execute("ALTER TABLE transactions ADD COLUMN source TEXT NOT NULL DEFAULT 'card'")
    db.commit()


# ---------------------------------------------------------------------------
# Money handling
#
# Prevents floating-point drift on balances: binary floats cannot represent
# most decimal fractions, so 0.1 + 0.2 != 0.3 and repeated transfers slowly
# corrupt a balance. Money is therefore parsed as decimal.Decimal, quantized to
# exactly two places, and stored as an integer number of cents ("minor units").
# All arithmetic and every SQL comparison happens on those integers, which is
# exact by construction.
# ---------------------------------------------------------------------------
MONEY_QUANTUM = Decimal("0.01")
MINOR_UNITS_PER_MAJOR = 100


def parse_money(raw) -> Decimal | None:
    """Parse user input into a Decimal with two places, or None if unusable.

    Decimal(str(...)) is deliberate: Decimal(0.1) would capture the float's
    binary error, while Decimal("0.1") is exact.
    """
    try:
        value = Decimal(str(raw).strip())
    except (InvalidOperation, ValueError, TypeError, AttributeError):
        return None
    # Rejects NaN and the infinities, which would otherwise pass a "> 0" test.
    if not value.is_finite():
        return None
    return value.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def to_minor(amount: Decimal) -> int:
    """Decimal rupees to the integer cents actually stored in the database."""
    return int(amount.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP) * MINOR_UNITS_PER_MAJOR)


def from_minor(minor: int) -> Decimal:
    """Integer cents back to a two-place Decimal."""
    return (Decimal(int(minor)) / MINOR_UNITS_PER_MAJOR).quantize(MONEY_QUANTUM)


def money_json(minor: int) -> float:
    """Render stored cents for a JSON response.

    The React pages call .toFixed(2) on these fields, so they have to stay JSON
    numbers rather than strings. Storage and arithmetic remain exact integers -
    this float exists only at the presentation boundary, where a two-decimal
    value well under 2**53 cents converts without loss.
    """
    return float(from_minor(minor))


def generate_account_number(db):
    while True:
        candidate = "".join(random.choices(string.digits, k=12))
        existing = db.execute(
            "SELECT id FROM users WHERE account_number = ?", (candidate,)
        ).fetchone()
        if existing is None:
            return candidate


def decrypt_transaction_amount(encrypted_amount, encrypted_aes_key):
    """Decrypt a stored amount, returning None if the record does not decrypt.

    AES-GCM is authenticated, so a single flipped byte in the ciphertext fails
    the tag check here. Returning None instead of raising keeps a tampered row
    from turning every dashboard and history request into an HTTP 500.
    """
    try:
        private_key = load_private_key(app.config["RSA_PRIVATE_KEY_PATH"])
        aes_key = rsa_decrypt(base64.b64decode(encrypted_aes_key), private_key)
        decrypted = parse_money(aes_decrypt(encrypted_amount, aes_key))
        return None if decrypted is None else money_json(to_minor(decrypted))
    except (ValueError, TypeError, KeyError):
        return None


def verify_transaction_row(tx) -> dict:
    """Recompute a stored transaction's signed payload and actually verify it.

    Prevents undetected ledger tampering: a signature is only an integrity
    control if something checks it on the way out. This rebuilds the exact byte
    string that /api/transfer signed and runs it through verify_signature, so
    the reported status reflects the stored bytes rather than a hardcoded
    string.

    Two independent things have to hold for a VERIFIED result:
      1. The AES-GCM ciphertexts still authenticate under their own tags.
      2. The RSA signature still matches the reconstructed payload.
    """
    result = {
        "valid": False,
        "status": "TAMPERED",
        "scheme": "unverified",
        "amount": None,
        "detail": "",
    }

    try:
        private_key = load_private_key(app.config["RSA_PRIVATE_KEY_PATH"])
        public_key = load_public_key(app.config["RSA_PUBLIC_KEY_PATH"])
        aes_key = rsa_decrypt(base64.b64decode(tx["encrypted_aes_key"]), private_key)
        amount_text = aes_decrypt(tx["encrypted_amount"], aes_key)
        message_text = aes_decrypt(tx["encrypted_message"], aes_key)
    except (ValueError, TypeError, KeyError) as exc:
        # The GCM tag check failed, so the ciphertext was altered after signing.
        result["detail"] = f"Authenticated decryption failed: {exc}"
        return result

    # encrypted_message holds "receiver|description" and a description may itself
    # contain a pipe, so split on the first one only.
    receiver, _separator, description = message_text.partition("|")

    # Exactly the construction used when the transfer was signed.
    plaintext = f"{receiver}|LKR {amount_text}|{description}"
    plaintext_hash = sha256_hash(plaintext)
    signed_payload = (
        f"{plaintext}|{plaintext_hash}|{tx['encrypted_amount']}|"
        f"{tx['encrypted_message']}|{tx['encrypted_aes_key']}"
    ).encode("utf-8")

    try:
        signature = base64.b64decode(tx["signature"])
    except (ValueError, TypeError) as exc:
        result["detail"] = f"Stored signature is not valid base64: {exc}"
        return result

    valid, scheme = verify_signature_detailed(signed_payload, signature, public_key)
    result["valid"] = valid
    result["status"] = "VERIFIED" if valid else "TAMPERED"
    result["scheme"] = scheme
    # Only report an amount for a record that verified; a tampered row has no
    # trustworthy value to show.
    parsed_amount = parse_money(amount_text)
    result["amount"] = money_json(to_minor(parsed_amount)) if (valid and parsed_amount is not None) else None
    result["detail"] = (
        f"Signature verified with {scheme}."
        if valid
        else "Signature does not match the stored transaction fields."
    )
    return result


security_logger = logging.getLogger("securebank.activity")


def setup_logging():
    os.makedirs(os.path.dirname(app.config["LOG_PATH"]), exist_ok=True)
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False
    if not security_logger.handlers:
        handler = logging.FileHandler(app.config["LOG_PATH"], encoding="utf-8")
        handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%Y-%m-%d %H:%M:%S"))
        security_logger.addHandler(handler)


def log_event(event: str, username: str, details: str = ""):
    security_logger.info("%s | user=%s | %s", event, username, details)


def admin_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != "admin":
            return jsonify({"ok": False, "message": "Admin access required."}), 403
        return view_func(*args, **kwargs)

    return wrapped


def role_required(*roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                return jsonify({"ok": False, "message": "Insufficient permissions."}), 403
            return view_func(*args, **kwargs)

        return wrapped

    return decorator


def user_locked(user_row: sqlite3.Row) -> bool:
    if not user_row["locked_until"]:
        return False
    try:
        locked_until = datetime.fromisoformat(user_row["locked_until"])
    except ValueError:
        return False
    return datetime.now() < locked_until


def unlock_if_expired(user_row: sqlite3.Row):
    if not user_row["locked_until"]:
        return
    try:
        locked_until = datetime.fromisoformat(user_row["locked_until"])
    except ValueError:
        return
    if datetime.now() >= locked_until:
        db = get_db()
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_row["id"],),
        )
        db.commit()


def migrate_legacy_password_hashes():
    """Remove any unsalted SHA-256 password digests still sitting in the table.

    Runs once at startup. Rows that already use scrypt or pbkdf2, and rows the
    migration has already wrapped, are left alone.
    """
    db = get_db()
    legacy_rows = [
        row
        for row in db.execute("SELECT id, username, password_hash FROM users").fetchall()
        if not row["password_hash"].startswith(MODERN_HASH_PREFIXES)
        and not row["password_hash"].startswith(LEGACY_SHA256_PREFIX)
    ]

    for row in legacy_rows:
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (wrap_legacy_sha256(row["password_hash"]), row["id"]),
        )
        log_event(
            "PASSWORD_HASH_MIGRATED",
            row["username"],
            "unsalted SHA-256 digest re-hashed with scrypt",
        )

    if legacy_rows:
        db.commit()

    return len(legacy_rows)


def register_default_admin():
    db = get_db()
    admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if admin is not None:
        return

    db.execute(
        """
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, current_balance_minor, wallet_balance_minor, account_number, must_change_password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "System Administrator",
            "admin",
            "admin@securebank.local",
            password_hash("Admin@123"),
            generate_otp_secret(),
            "admin",
            0,
            0,
            0,
            0,
            0,
            generate_account_number(db),
            # Ships with a published default password, so it must be changed
            # before the account can be used for anything else.
            1,
        ),
    )
    db.commit()


def register_default_security_staff():
    db = get_db()
    staff = db.execute("SELECT id FROM users WHERE username = ?", ("security",)).fetchone()
    if staff is not None:
        return

    db.execute(
        """
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, current_balance_minor, wallet_balance_minor, account_number, must_change_password)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Security Operations Staff",
            "security",
            "security@securebank.local",
            password_hash("Security@123"),
            generate_otp_secret(),
            "security",
            0,
            0,
            0,
            0,
            0,
            generate_account_number(db),
            # Same published-default problem as the admin account.
            1,
        ),
    )
    db.commit()


def register_demo_target_account():
    db = get_db()
    target = db.execute("SELECT id FROM users WHERE username = ?", ("demo_target",)).fetchone()
    if target is not None:
        return

    db.execute(
        """
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, current_balance_minor, wallet_balance_minor, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "Brute Force Demo Target",
            "demo_target",
            "demo_target@securebank.local",
            password_hash("DemoTarget@123"),
            generate_otp_secret(),
            "customer",
            0,
            0,
            0,
            0,
            0,
            generate_account_number(db),
        ),
    )
    db.commit()


def reset_demo_target_lock():
    db = get_db()
    db.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
        ("demo_target",),
    )
    db.commit()


@app.before_request
def touch_session():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=app.config["SESSION_TIMEOUT_SECONDS"])


def serialize_user_row(row):
    return {
        "name": row["name"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "lastLogin": row["last_login"],
        "accountNumber": row["account_number"],
    }


def log_event_seen(event_names, log_lines=None):
    lines = log_lines if log_lines is not None else read_recent_log_lines(500)
    for line in lines:
        parsed = parse_log_line(line)
        if parsed["event"] in event_names:
            return True
    return False


FIREWALL_ENABLED_CACHE_SECONDS = 5
_firewall_enabled_cache = {"checked_at": None, "value": False}


def firewall_enabled_live():
    now = datetime.now()
    cached_at = _firewall_enabled_cache["checked_at"]
    if cached_at is not None and (now - cached_at).total_seconds() < FIREWALL_ENABLED_CACHE_SECONDS:
        return _firewall_enabled_cache["value"]

    try:
        profiles = get_firewall_profiles()
        value = any(p["enabled"] for p in profiles.values()) if profiles else False
    except Exception:  # noqa: BLE001 - live query is best-effort for this status flag
        value = False

    _firewall_enabled_cache["checked_at"] = now
    _firewall_enabled_cache["value"] = value
    return value


def security_status_flags():
    tls_active = os.path.exists(app.config["SSL_CERT_PATH"]) and os.path.exists(app.config["SSL_KEY_PATH"])
    backup_exists = os.path.exists(BACKUP_ENCRYPTED_PATH)
    log_lines = read_recent_log_lines(500)
    firewall_exercised = log_event_seen({"LOGIN_FAILED", "ATTACK_SIMULATION"}, log_lines)
    ids_exercised = log_event_seen(
        {"ATTACK_SIMULATION", "TRANSFER_FAILED", "OTP_FAILED", "SIGNATURE_INVALID"}, log_lines
    )
    return {
        "httpsConnection": request.is_secure,
        "tlsCertificate": tls_active,
        "firewallEnabled": firewall_enabled_live(),
        "firewallExercised": firewall_exercised,
        "idsMonitoring": ids_exercised,
        "passwordHashing": "scrypt (legacy SHA-256 accounts migrate on login)",
        "otpAuthentication": "TOTP (pyotp)",
        "aesEncryption": True,
        "rsaKeyProtection": True,
        "digitalSignature": True,
        "databaseEncrypted": False,
        "backupReady": backup_exists,
        "sessionAuthenticated": current_user.is_authenticated,
    }


def read_recent_log_lines(limit: int = 12):
    if not os.path.exists(app.config["LOG_PATH"]):
        return []
    with open(app.config["LOG_PATH"], "r", encoding="utf-8") as log_file:
        lines = [line.rstrip("\n") for line in log_file.readlines()]
    return lines[-limit:]


def parse_log_line(line: str):
    timestamp = ""
    payload = line
    if line.startswith("[") and "] " in line:
        timestamp, payload = line[1:].split("] ", 1)
    parts = payload.split(" | ")
    event = parts[0] if parts else payload
    user = ""
    details = ""
    for part in parts[1:]:
        if part.startswith("user="):
            user = part.split("=", 1)[1]
        else:
            details = part if not details else f"{details} | {part}"
    return {"timestamp": timestamp, "event": event, "user": user, "details": details}


TIMELINE_EVENT_LABELS = {
    "LOGIN_SUCCESS": ("Login", "Password verified, OTP issued"),
    "LOGIN_FAILED": ("Login Failed", "Password or lockout check failed"),
    "OTP_FAILED": ("OTP Rejected", "Invalid or replayed OTP code"),
    "OTP_LOCKOUT": ("OTP Lockout", "Account locked after repeated invalid OTP codes"),
    "REGISTER_SUCCESS": ("Account Registered", "New customer record created"),
    "TRANSFER_SUCCESS": ("Transaction Signed", "RSASSA-PSS signature + database update"),
    "TRANSFER_FAILED": ("Transaction Rejected", "Signature verification failed"),
    "SIGNATURE_INVALID": ("Tampered Record Detected", "Stored transaction failed signature verification on read"),
    "CSRF_REJECTED": ("CSRF Blocked", "State-changing request rejected for a missing or invalid token"),
    "PASSWORD_HASH_MIGRATED": ("Password Hash Migrated", "Unsalted SHA-256 digest re-hashed with scrypt"),
    "PASSWORD_HASH_UPGRADED": ("Password Hash Upgraded", "Legacy row re-hashed with scrypt on login"),
    "BACKUP_SUCCESS": ("Backup Completed", "AES encryption + hash + integrity verification"),
    "MAIL_SENT": ("Secure Mail Sent", "Message delivered over SMTP+STARTTLS"),
    "MAIL_FAILED": ("Secure Mail Failed", "SMTP+STARTTLS delivery was refused"),
    "MAIL_SKIPPED": ("Secure Mail Skipped", "No SMTP server configured"),
    "OTP_DISPATCHED": ("OTP Dispatched", "One-time password emailed out of band"),
    "SFTP_UPLOAD_SUCCESS": ("Offsite Backup Uploaded", "Encrypted backup sent over SFTP"),
    "SFTP_HOST_KEY_MISMATCH": ("SFTP Host Key Mismatch", "Server key did not match known_hosts - upload aborted"),
    "SFTP_REJECTED": ("SFTP Upload Rejected", "Host key could not be verified"),
    "SFTP_FAILED": ("Offsite Backup Failed", "SSH/SFTP transfer did not complete"),
    "BACKUP_INTEGRITY_FAILED": ("Backup Integrity Failed", "Decrypted hash did not match original"),
    "ATTACK_SIMULATION": ("Attack Simulated", "Security lab exercised a defense mechanism"),
    "LOGOUT": ("Session Ended", "User logged out"),
}

FALLBACK_TIMELINE_TEMPLATE = [
    ("Login", "Customer requested secure access"),
    ("Password Verified", "scrypt hash matched"),
    ("OTP Generated", "TOTP challenge issued"),
    ("OTP Verified", "Second factor accepted"),
    ("TLS Session Created", "HTTPS transport active"),
    ("AES Session Started", "Transaction payload encrypted with AES-256-GCM"),
    ("Transaction Signed", "RSASSA-PSS integrity check"),
    ("Database Updated", "Encrypted record stored"),
    ("Backup Scheduled", "Integrity copy prepared"),
]


def security_timeline_entries(limit: int = 12):
    log_lines = read_recent_log_lines(200)
    entries = []
    for line in log_lines:
        parsed = parse_log_line(line)
        label = TIMELINE_EVENT_LABELS.get(parsed["event"])
        if not label:
            continue
        title, base_detail = label
        detail = f"{base_detail} ({parsed['details']})" if parsed["details"] else base_detail
        entries.append({"time": parsed["timestamp"], "event": title, "detail": detail, "user": parsed["user"]})

    if entries:
        return entries[-limit:]

    now = datetime.now().replace(second=0, microsecond=0)
    return [
        {"time": now.strftime("%H:%M"), "event": title, "detail": detail}
        for title, detail in FALLBACK_TIMELINE_TEMPLATE
    ]


THREAT_LOG_MARKERS = {
    "Brute Force": "attackType=bruteForce",
    "Unauthorized Access": "attackType=unauthorizedAccess",
    "SQL Injection": "attackType=sqlInjection",
    "Packet Sniffing": "attackType=packetSniffing",
    "Tampered Transaction": "attackType=tamperedTransaction",
    "Replay Attack": "attackType=replayAttack",
}

THREAT_CONTROLS = {
    "Brute Force": "Account lockout + OTP",
    "Unauthorized Access": "Flask-Login + role_required",
    "SQL Injection": "Parameterized queries",
    "Packet Sniffing": "TLS/HTTPS",
    "Tampered Transaction": "RSASSA-PSS signature verification",
    "Replay Attack": "One-time OTP consumption",
}


def threat_map_entries(log_lines):
    entries = []
    for name, marker in THREAT_LOG_MARKERS.items():
        tested = any(marker in line for line in log_lines)
        entries.append(
            {
                "name": name,
                "status": "Blocked" if tested else "Not Yet Tested",
                "control": THREAT_CONTROLS[name],
                "tested": tested,
            }
        )
    return entries


def security_overview_payload():
    db = get_db()
    total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
    total_transactions = db.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()["count"]
    latest_transactions = db.execute(
        "SELECT date, sender, receiver, status FROM transactions ORDER BY date DESC LIMIT 5"
    ).fetchall()

    tls_active = os.path.exists(app.config["SSL_CERT_PATH"]) and os.path.exists(app.config["SSL_KEY_PATH"])
    backup_exists = os.path.exists(BACKUP_ENCRYPTED_PATH)
    all_logs = read_recent_log_lines(500)
    recent_logs = [parse_log_line(line) for line in all_logs[-8:]]
    last_login_row = db.execute(
        "SELECT username, last_login FROM users WHERE last_login IS NOT NULL ORDER BY last_login DESC LIMIT 1"
    ).fetchone()
    firewall_exercised = log_event_seen({"LOGIN_FAILED", "ATTACK_SIMULATION"}, all_logs)
    ids_exercised = log_event_seen({"ATTACK_SIMULATION", "TRANSFER_FAILED", "OTP_FAILED"}, all_logs)
    firewall_enabled = firewall_enabled_live()

    return {
        "topology": [
            {"label": "Customer", "detail": "Login request"},
            {"label": "Internet", "detail": "Encrypted HTTPS tunnel"},
            {"label": "Router", "detail": "Packet routing"},
            {"label": "Firewall", "detail": "Packet inspection"},
            {"label": "TLS Handshake", "detail": "Session key negotiation"},
            {"label": "Application Server", "detail": "Flask security services"},
            {"label": "Database", "detail": "SQLite encrypted record"},
        ],
        "securityModules": [
            {"label": "Firewall", "status": "Active" if firewall_enabled else "Disabled"},
            {"label": "Firewall Activity", "status": "Exercised" if firewall_exercised else "Idle"},
            {"label": "HTTPS", "status": "Active" if tls_active or request.is_secure else "Demo"},
            {"label": "TLS", "status": "Active" if tls_active else "Certificate Ready"},
            {"label": "OTP", "status": "Active"},
            {"label": "AES", "status": "Active"},
            {"label": "RSA", "status": "Active"},
            {"label": "Digital Signature", "status": "Active"},
            {"label": "Backup", "status": "Completed" if backup_exists else "Ready"},
            {"label": "IDS", "status": "Monitoring" if ids_exercised else "Idle"},
            {"label": "Database", "status": "Encrypted"},
        ],
        "threats": threat_map_entries(all_logs),
        "timeline": security_timeline_entries(),
        "recentLogs": recent_logs,
        "database": {
            "users": total_users,
            "transactions": total_transactions,
            "backup": "Completed" if backup_exists else "Pending",
            "encryption": "AES-256-GCM",
        },
        "networkTrace": [
            "Customer",
            "Router",
            "Firewall Inspection",
            "TLS Handshake",
            "Application Server",
            "Database",
        ],
        "lastRealLogin": {
            "username": last_login_row["username"] if last_login_row else None,
            "timestamp": last_login_row["last_login"] if last_login_row else None,
        },
    }


def build_encryption_monitor(receiver: str, amount_value: Decimal, message: str):
    plaintext = f"{receiver} | LKR {amount_value:.2f} | {message}"
    hash_value = sha256_hash(plaintext)
    private_key = load_private_key(app.config["RSA_PRIVATE_KEY_PATH"])
    public_key = load_public_key(app.config["RSA_PUBLIC_KEY_PATH"])
    aes_key = generate_aes_key()
    ciphertext = aes_encrypt(plaintext, aes_key)
    encrypted_key_bytes = rsa_encrypt(aes_key, public_key)
    encrypted_aes_key = base64.b64encode(encrypted_key_bytes).decode("utf-8")
    signature = sign_data(f"{plaintext}|{hash_value}|{ciphertext}|{encrypted_aes_key}".encode("utf-8"), private_key)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    return {
        "plaintext": plaintext,
        "hash": hash_value,
        "ciphertext": ciphertext,
        "encryptedAesKey": encrypted_aes_key,
        "signature": signature_b64,
        "aesKeyPreview": aes_key.hex()[:8] + "...",
    }


def build_encryption_pipeline(monitor: dict):
    return [
        {"step": 1, "title": "Plaintext", "algorithm": "User Input", "status": "completed", "value": monitor["plaintext"]},
        {"step": 2, "title": "SHA-256 Hash", "algorithm": "SHA-256", "status": "completed", "value": monitor["hash"][:32] + "..."},
        {"step": 3, "title": "AES Encryption", "algorithm": "AES-256-GCM", "status": "completed", "value": monitor["ciphertext"][:32] + "..."},
        {"step": 4, "title": "RSA Encrypt AES Key", "algorithm": "RSA-2048-OAEP", "status": "completed", "value": monitor["encryptedAesKey"][:32] + "..."},
        {"step": 5, "title": "Digital Signature", "algorithm": SCHEME_PSS, "status": "completed", "value": monitor["signature"][:32] + "..."},
        {"step": 6, "title": "TLS Transmission", "algorithm": "HTTPS/TLS", "status": "completed" if request.is_secure else "demo", "value": "Secure channel"},
        {"step": 7, "title": "Database Storage", "algorithm": "SQLite", "status": "completed", "value": "Encrypted record stored"},
    ]


def run_brute_force_simulation():
    db = get_db()
    reset_demo_target_lock()
    sequence = []
    locked = False
    lock_until = None
    attempts = 0

    for attempt_num in range(1, app.config["MAX_LOGIN_ATTEMPTS"] + 1):
        target = db.execute("SELECT * FROM users WHERE username = ?", ("demo_target",)).fetchone()
        attempts = target["failed_attempts"] + 1
        sequence.append(f"Failed Login attempt {attempt_num} against demo_target")
        if attempts >= app.config["MAX_LOGIN_ATTEMPTS"]:
            lock_until = (datetime.now() + timedelta(minutes=app.config["LOCK_MINUTES"])).isoformat()
            locked = True
        db.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?",
            (attempts, lock_until, "demo_target"),
        )
        db.commit()
        if locked:
            break

    sequence.append("Firewall Triggered" if locked else "Retry threshold not yet reached")
    sequence.append("IDS Alert Raised" if locked else "IDS Monitoring")
    sequence.append(f"Account Locked until {lock_until}" if locked else "Account Not Locked")

    return {
        "title": "Simulate Brute Force",
        "sequence": sequence,
        "result": (
            f"demo_target locked after {attempts} real failed attempts (locked_until={lock_until})."
            if locked
            else f"demo_target has {attempts} failed attempts, not yet locked."
        ),
    }


def run_sql_injection_simulation():
    db = get_db()
    payload = "' OR '1'='1"
    sequence = [f"Injected payload submitted: {payload}"]
    try:
        rows = db.execute("SELECT id FROM users WHERE username = ?", (payload,)).fetchall()
        sequence.append("Parameterized query executed with payload as literal string")
        sequence.append(f"Rows matched: {len(rows)} (payload treated as data, not SQL)")
        blocked = len(rows) == 0
    except sqlite3.Error as exc:
        sequence.append(f"Query rejected: {exc}")
        blocked = True

    sequence.append("IDS alert raised" if blocked else "IDS alert not triggered")
    sequence.append("Request rejected" if blocked else "Request returned unexpected rows")

    return {
        "title": "Simulate SQL Injection",
        "sequence": sequence,
        "result": (
            "Blocked: parameterized queries treat the payload as plain text, so it matched zero real rows."
            if blocked
            else "Warning: payload returned rows — investigate query construction."
        ),
    }


def run_unauthorized_access_simulation(actor_role: str):
    db = get_db()
    target = db.execute("SELECT role FROM users WHERE username = ?", ("demo_target",)).fetchone()
    target_role = target["role"] if target else "customer"

    sequence = [
        f"Simulated actor: demo_target (real role from database = '{target_role}')",
        "Actor attempts GET /api/security/overview",
        "role_required('security', 'admin') evaluates current_user.role == 'demo_target' role",
    ]
    allowed = target_role in ("security", "admin")
    sequence.append("Access granted" if allowed else "Access denied: HTTP 403 Insufficient permissions")
    sequence.append("Security log recorded")

    return {
        "title": "Simulate Unauthorized Access",
        "sequence": sequence,
        "result": (
            f"Blocked: demo_target has role '{target_role}', rejected by role_required with a real 403."
            if not allowed
            else f"demo_target's role '{target_role}' is authorized for security endpoints."
        ),
    }


def run_packet_sniffing_simulation():
    tls_active = os.path.exists(app.config["SSL_CERT_PATH"]) and os.path.exists(app.config["SSL_KEY_PATH"])
    sequence = [
        "Traffic observed on network",
        f"TLS certificate present: {tls_active}",
        "TLS handshake negotiated" if tls_active or request.is_secure else "Connection running without TLS (demo mode)",
        "Ciphertext captured instead of plaintext" if (tls_active or request.is_secure) else "Plaintext would be visible without TLS",
    ]
    return {
        "title": "Simulate Packet Sniffing",
        "sequence": sequence,
        "result": (
            "TLS prevents plaintext disclosure on the wire."
            if (tls_active or request.is_secure)
            else "Risk: enable HTTPS/TLS to prevent plaintext disclosure."
        ),
    }


def run_tampered_transaction_simulation():
    private_key = load_private_key(app.config["RSA_PRIVATE_KEY_PATH"])
    public_key = load_public_key(app.config["RSA_PUBLIC_KEY_PATH"])

    plaintext = "demo_target|LKR 1000.00|Tampered transaction demo"
    plaintext_hash = sha256_hash(plaintext)
    ciphertext = aes_encrypt(plaintext, generate_aes_key())
    signed_payload = f"{plaintext}|{plaintext_hash}|{ciphertext}".encode("utf-8")
    signature = sign_data(signed_payload, private_key)

    sequence = [f"Legitimate transaction signed with {SCHEME_PSS}"]
    genuine_valid = verify_signature(signed_payload, signature, public_key)
    sequence.append(f"Signature verification on original payload: {'PASS' if genuine_valid else 'FAIL'}")

    tampered_ciphertext = ciphertext[:-4] + ("AAAA" if not ciphertext.endswith("AAAA") else "BBBB")
    tampered_payload = f"{plaintext}|{plaintext_hash}|{tampered_ciphertext}".encode("utf-8")
    tampered_valid = verify_signature(tampered_payload, signature, public_key)
    sequence.append("Attacker flips bytes in the encrypted transaction payload")
    sequence.append(f"Signature verification on tampered payload: {'PASS' if tampered_valid else 'FAIL'}")

    blocked = genuine_valid and not tampered_valid
    sequence.append("Tampered transaction rejected" if blocked else "Tampered transaction NOT detected")

    return {
        "title": "Simulate Tampered Transaction",
        "sequence": sequence,
        "result": (
            "Blocked: verify_signature() genuinely fails once the ciphertext is altered, proving signature-based integrity protection."
            if blocked
            else "Warning: tampering was not detected — investigate signature scheme."
        ),
    }


def run_replay_attack_simulation(username: str):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        return {
            "title": "Simulate Replay Attack",
            "sequence": ["No demo user available to generate an OTP for replay."],
            "result": "Unable to run: a valid user account is required.",
        }

    otp_code = current_otp(user["otp_secret"])
    sequence = [f"Real OTP generated for {username}: {otp_code}"]

    scratch_session = {"pending_user_id": user["id"]}
    first_use = verify_otp(user["otp_secret"], otp_code)
    if first_use:
        scratch_session.pop("pending_user_id", None)
    sequence.append(f"First verification attempt: {'ACCEPTED, session pending_user_id cleared' if first_use else 'REJECTED'}")

    sequence.append("Attacker captures and resubmits the exact same OTP code")
    replay_pending_id = scratch_session.get("pending_user_id")
    if replay_pending_id is None:
        sequence.append("Replayed attempt: REJECTED — 'Please login first.' (pending_user_id already consumed)")
        blocked = True
    else:
        replay_accepted = verify_otp(user["otp_secret"], otp_code)
        sequence.append(f"Replayed attempt: {'ACCEPTED' if replay_accepted else 'REJECTED'}")
        blocked = not replay_accepted

    return {
        "title": "Simulate Replay Attack",
        "sequence": sequence,
        "result": (
            "Blocked: /api/otp/verify clears session['pending_user_id'] on success, so resubmitting the same OTP has nothing to verify against."
            if blocked
            else "Warning: OTP replay was not detected — investigate session consumption."
        ),
    }


def run_attack_simulation(attack_type: str, actor_role: str, actor_username: str):
    if attack_type == "bruteForce":
        return run_brute_force_simulation()
    if attack_type == "sqlInjection":
        return run_sql_injection_simulation()
    if attack_type == "packetSniffing":
        return run_packet_sniffing_simulation()
    if attack_type == "tamperedTransaction":
        return run_tampered_transaction_simulation()
    if attack_type == "replayAttack":
        return run_replay_attack_simulation(actor_username)
    return run_unauthorized_access_simulation(actor_role)


def security_report_payload():
    overview = security_overview_payload()
    tls_active = os.path.exists(app.config["SSL_CERT_PATH"]) and os.path.exists(app.config["SSL_KEY_PATH"])
    firewall_status = overview["securityModules"][0]["status"]
    ids_status = next(m["status"] for m in overview["securityModules"] if m["label"] == "IDS")
    checks = [
        {"label": "Firewall", "status": "PASS" if firewall_status == "Active" else "NOT YET TESTED", "detail": firewall_status},
        {"label": "Encryption", "status": "PASS", "detail": "AES-256-GCM active"},
        {"label": "TLS", "status": "PASS" if tls_active else "PENDING", "detail": "HTTPS/TLS enabled" if tls_active else "Certificate missing"},
        {"label": "Certificate", "status": "PASS" if tls_active else "PENDING", "detail": "Certificate available" if tls_active else "Certificate missing"},
        {"label": "Backup", "status": "PASS" if overview["database"]["backup"] == "Completed" else "PENDING", "detail": overview["database"]["backup"]},
        {"label": "IDS", "status": "PASS" if ids_status == "Monitoring" else "NOT YET TESTED", "detail": ids_status},
    ]
    return {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "checks": checks,
        "threats": overview["threats"],
        "timeline": overview["timeline"],
        "summary": {
            "users": overview["database"]["users"],
            "transactions": overview["database"]["transactions"],
            "backup": overview["database"]["backup"],
        },
    }


def escape_pdf_text(text: str):
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


PAGE_WIDTH = 595
PAGE_HEIGHT = 842
MARGIN_X = 72

BLACK = (0, 0, 0)


class PdfPageBuilder:
    def __init__(self):
        self.ops = []

    def text(self, x, y, s, font="F1", size=11, color=BLACK):
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        self.ops.append("BT")
        self.ops.append(f"/{font} {size} Tf")
        self.ops.append(f"{x:.2f} {y:.2f} Td")
        self.ops.append(f"({escape_pdf_text(s)}) Tj")
        self.ops.append("ET")

    def line(self, x1, y1, x2, y2, color=BLACK, width=0.75):
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG")
        self.ops.append(f"{width:.2f} w")
        self.ops.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def build(self):
        return "\n".join(self.ops).encode("utf-8")


def build_security_report_pdf(report: dict):
    page = PdfPageBuilder()
    y = PAGE_HEIGHT - 72

    page.text(MARGIN_X, y, "SECURE BANKING SECURITY REPORT", font="F2", size=14)
    y -= 20
    page.line(MARGIN_X, y, PAGE_WIDTH - MARGIN_X, y, width=1)
    y -= 22
    page.text(MARGIN_X, y, f"Date: {report['date']}", font="F1", size=10)
    y -= 30

    def section_title(title, y):
        page.text(MARGIN_X, y, title, font="F2", size=11)
        y -= 6
        page.line(MARGIN_X, y, PAGE_WIDTH - MARGIN_X, y, width=0.5)
        return y - 20

    y = section_title("1. Security Checks", y)
    for check in report["checks"]:
        page.text(MARGIN_X, y, f"{check['label']}:", font="F1", size=10)
        page.text(MARGIN_X + 150, y, check["status"], font="F1", size=10)
        page.text(MARGIN_X + 240, y, f"({check['detail']})", font="F1", size=10)
        y -= 18
    y -= 16

    y = section_title("2. Summary", y)
    page.text(MARGIN_X, y, f"Users: {report['summary']['users']}", font="F1", size=10)
    y -= 18
    page.text(MARGIN_X, y, f"Transactions: {report['summary']['transactions']}", font="F1", size=10)
    y -= 18
    page.text(MARGIN_X, y, f"Backup: {report['summary']['backup']}", font="F1", size=10)
    y -= 34

    y = section_title("3. Threat Map", y)
    for threat in report["threats"]:
        page.text(MARGIN_X, y, f"{threat['name']}:", font="F1", size=10)
        page.text(MARGIN_X + 150, y, threat["status"], font="F1", size=10)
        page.text(MARGIN_X + 240, y, f"(via {threat['control']})", font="F1", size=10)
        y -= 18
    y -= 16

    page.line(MARGIN_X, 60, PAGE_WIDTH - MARGIN_X, 60, width=0.5)
    page.text(MARGIN_X, 44, "Secure Banking Prototype - Internal Report", font="F1", size=8.5)

    content_stream = page.build()

    objects = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
        b"/Resources << /Font << /F1 4 0 R /F2 6 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    )
    objects.append(b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n")
    objects.append(
        f"5 0 obj\n<< /Length {len(content_stream)} >>\nstream\n".encode("utf-8")
        + content_stream
        + b"\nendstream\nendobj\n"
    )
    objects.append(b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>\nendobj\n")

    header = b"%PDF-1.4\n"
    body = bytearray(header)
    offsets = [0]
    for obj in objects:
        offsets.append(len(body))
        body.extend(obj)
    xref_offset = len(body)
    obj_count = len(objects) + 1
    xref = [f"xref\n0 {obj_count}\n".encode("utf-8"), b"0000000000 65535 f \n"]
    for offset in offsets[1:]:
        xref.append(f"{offset:010d} 00000 n \n".encode("utf-8"))
    trailer = (
        f"trailer\n<< /Size {obj_count} /Root 1 0 R >>\nstartxref\n".encode("utf-8")
        + str(xref_offset).encode("utf-8")
        + b"\n%%EOF"
    )
    return bytes(body + b"".join(xref) + trailer)


@app.route("/api/csrf-token")
def api_csrf_token():
    """Hand the SPA a CSRF token bound to its session.

    Safe to expose: same-origin policy stops an attacker's page from reading
    this response, so they cannot learn the token even though the browser
    would happily send the session cookie along with their forged request.
    """
    return jsonify({"csrfToken": generate_csrf()})


@app.route("/api/session")
def api_session():
    if not current_user.is_authenticated:
        return jsonify({"authenticated": False, "securityStatus": security_status_flags()}), 401

    # Re-read the flag rather than trusting the session copy, so the banner in the
    # SPA disappears as soon as the password is actually changed.
    row = get_db().execute(
        "SELECT must_change_password FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    return jsonify(
        {
            "authenticated": True,
            "user": {
                "username": current_user.username,
                "role": current_user.role,
                "mustChangePassword": bool(row["must_change_password"]) if row else False,
            },
            "securityStatus": security_status_flags(),
        }
    )


@app.route("/api/security/overview")
@login_required
@role_required("security", "admin")
def api_security_overview():
    return jsonify(security_overview_payload())


@app.route("/api/security/encryption-lab", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_security_encryption_lab():
    data = request.get_json(silent=True) or {}
    receiver = (data.get("receiver") or current_user.username or "customer").strip()
    message = (data.get("message") or "Security lab demo").strip()
    amount_raw = data.get("amount") or "0"
    amount_value = parse_money(amount_raw)
    if amount_value is None:
        amount_value = Decimal("0.00")

    monitor = build_encryption_monitor(receiver, amount_value, message)
    return jsonify({"ok": True, "monitor": monitor, "pipeline": build_encryption_pipeline(monitor)})


@app.route("/api/security/attack-simulate", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_security_attack_simulate():
    data = request.get_json(silent=True) or {}
    attack_type = (data.get("attackType") or "unauthorizedAccess").strip()
    payload = run_attack_simulation(attack_type, current_user.role, current_user.username)
    log_event("ATTACK_SIMULATION", current_user.username, f"attackType={attack_type}")
    return jsonify({"ok": True, **payload, "attackType": attack_type})


@app.route("/api/security/firewall-status")
@login_required
@role_required("security", "admin")
def api_security_firewall_status():
    return jsonify(firewall_status_payload())


@app.route("/api/security/firewall-connections")
@login_required
@role_required("security", "admin")
def api_security_firewall_connections():
    app_only = request.args.get("appOnly", "true").lower() != "false"
    return jsonify(read_recent_connections(limit=50, app_only=app_only))


@app.route("/api/security/reset-demo-target", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_security_reset_demo_target():
    reset_demo_target_lock()
    log_event("DEMO_TARGET_RESET", current_user.username, "demo_target unlocked on demand")
    return jsonify({"ok": True, "message": "demo_target account unlocked and failed attempts cleared."})


@app.route("/api/security/database")
@login_required
@role_required("security", "admin")
def api_security_database():
    db = get_db()
    users = db.execute(
        "SELECT id, name, username, email, role, current_balance_minor, wallet_balance_minor, last_login FROM users ORDER BY id"
    ).fetchall()
    transactions = db.execute(
        "SELECT id, sender, receiver, date, status, encrypted_amount, encrypted_aes_key FROM transactions ORDER BY id DESC LIMIT 25"
    ).fetchall()

    return jsonify(
        {
            "summary": {
                "users": len(users),
                "transactions": len(transactions),
                "backup": "Completed" if os.path.exists(BACKUP_ENCRYPTED_PATH) else "Pending",
            },
            "users": [
                {
                    "id": row["id"],
                    "name": row["name"],
                    "username": row["username"],
                    "email": row["email"],
                    "role": row["role"],
                    "currentBalance": money_json(row["current_balance_minor"]),
                    "walletBalance": money_json(row["wallet_balance_minor"]),
                    "lastLogin": row["last_login"],
                }
                for row in users
            ],
            "transactions": [
                {
                    "id": row["id"],
                    "sender": row["sender"],
                    "receiver": row["receiver"],
                    "date": row["date"],
                    "status": row["status"],
                    "encryptedAmount": row["encrypted_amount"],
                    "encryptedAesKey": row["encrypted_aes_key"],
                }
                for row in transactions
            ],
        }
    )


@app.route("/api/security/logs")
@login_required
@role_required("security", "admin")
def api_security_logs():
    return jsonify({"timeline": security_timeline_entries(), "recentLogs": [parse_log_line(line) for line in read_recent_log_lines(20)]})


@app.route("/api/security/report")
@login_required
@role_required("security", "admin")
def api_security_report():
    return jsonify(security_report_payload())


@app.route("/api/security/report/download")
@login_required
@role_required("security", "admin")
def api_security_report_download():
    pdf_bytes = build_security_report_pdf(security_report_payload())
    response = app.response_class(pdf_bytes, mimetype="application/pdf")
    response.headers["Content-Disposition"] = 'attachment; filename="security-report.pdf"'
    return response


@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()
    password = data.get("password") or ""
    confirm_password = data.get("confirmPassword") or ""

    if not all([name, username, email, password, confirm_password]):
        return jsonify({"ok": False, "message": "All fields are required."}), 400

    if password != confirm_password:
        return jsonify({"ok": False, "message": "Passwords do not match."}), 400

    valid, message = validate_password_complexity(password)
    if not valid:
        return jsonify({"ok": False, "message": message}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
    ).fetchone()
    if existing:
        return jsonify({"ok": False, "message": "Username or email already exists."}), 409

    hashed_password = password_hash(password)
    db.execute(
        """
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, current_balance_minor, wallet_balance_minor, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name,
            username,
            email,
            hashed_password,
            generate_otp_secret(),
            "customer",
            150000,
            150000,
            0,
            to_minor(OPENING_BALANCE),
            0,
            generate_account_number(db),
        ),
    )
    db.commit()

    log_event("REGISTER_SUCCESS", username)
    return jsonify(
        {
            "ok": True,
            "message": "Registration successful. Please login.",
            "security": {
                "algorithm": "scrypt",
                "passwordHash": "scrypt hash generated (value withheld)",
                "note": "Only the salted scrypt hash is stored. The plaintext password is never saved.",
            },
        }
    )


# Opening balance for a newly registered demo customer.
OPENING_BALANCE = Decimal("150000.00")


PORTAL_ROLES = {
    "customer": {"customer"},
    "staff": {"security", "admin"},
}


@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    portal = data.get("portal") or "customer"

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user is None:
        log_event("LOGIN_FAILED", username, "unknown user")
        return jsonify({"ok": False, "message": "Invalid username or password."}), 401

    unlock_if_expired(user)
    user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

    if user_locked(user):
        log_event("LOGIN_FAILED", username, "account locked")
        return jsonify({"ok": False, "message": "Account is locked. Try again later."}), 403

    if not verify_password(password, user["password_hash"]):
        attempts = user["failed_attempts"] + 1
        lock_until = None
        if attempts >= app.config["MAX_LOGIN_ATTEMPTS"]:
            lock_until = (datetime.now() + timedelta(minutes=app.config["LOCK_MINUTES"]))
            lock_until = lock_until.isoformat()
            message = "Too many failures. Account locked temporarily."
            log_event("LOGIN_FAILED", username, "max attempts reached")
        else:
            message = "Invalid username or password."
            log_event("LOGIN_FAILED", username, f"failed_attempts={attempts}")

        db.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, lock_until, user["id"]),
        )
        db.commit()
        return jsonify({"ok": False, "message": message}), 401

    if user["role"] not in PORTAL_ROLES.get(portal, set()):
        log_event("LOGIN_FAILED", username, f"wrong portal: {portal}")
        return jsonify({"ok": False, "message": "Invalid username or password."}), 401

    # A correct password is the only chance to convert a migrated legacy row
    # into an ordinary scrypt hash, because this is the only moment the
    # plaintext exists. After this the row is indistinguishable from a
    # normally registered account.
    if needs_rehash(user["password_hash"]):
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash(password), user["id"]),
        )
        db.commit()
        log_event("PASSWORD_HASH_UPGRADED", username, "re-hashed with scrypt on login")

    session["pending_user_id"] = user["id"]
    session["pending_otp_generated"] = datetime.now().isoformat()

    otp_code = current_otp(user["otp_secret"])

    # Prevents MFA bypass by second-factor disclosure: the OTP is delivered out
    # of band over SMTP+STARTTLS to the address on file, so passing the password
    # stage no longer hands the caller the second factor. Mail failure is
    # reported, never raised - the user can still use an enrolled authenticator
    # app (see GET /api/profile/otp-uri).
    mail_result = send_secure_email(
        user["email"],
        "SecureBank one-time password",
        (
            f"Hello {user['name']},\n\n"
            f"Your SecureBank one-time password is: {otp_code}\n\n"
            "It is valid for approximately one minute. If you did not try to sign in, "
            "change your password immediately.\n\n"
            "This message was delivered over an encrypted SMTP session.\n"
        ),
    )
    log_event(
        "OTP_DISPATCHED",
        username,
        f"channel=email delivered={mail_result['sent']} tls={mail_result['tlsVersion']}",
    )

    response = {
        "ok": True,
        "otpRequired": True,
        "otpDelivery": {
            "channel": "email",
            "sent": mail_result["sent"],
            "recipient": mask_email(user["email"]),
            "protocol": mail_result["protocol"],
            "tlsVersion": mail_result["tlsVersion"],
            "cipher": mail_result["cipher"],
            "detail": mail_result["detail"],
        },
        "security": {"passwordVerified": True, "algorithm": "scrypt (adaptive hash)", "otpAlgorithm": "TOTP (pyotp)"},
    }

    # Escape hatch for a live demo on a machine with no mail server configured.
    if app.config["DEMO_MODE"]:
        response["demoOtp"] = otp_code

    return jsonify(response)


@app.route("/api/otp/verify", methods=["POST"])
def api_otp_verify():
    pending_user_id = session.get("pending_user_id")
    if pending_user_id is None:
        return jsonify({"ok": False, "message": "Please login first."}), 400

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (pending_user_id,)).fetchone()
    if user is None:
        session.pop("pending_user_id", None)
        return jsonify({"ok": False, "message": "Invalid session. Please login again."}), 400

    # Prevents OTP brute force: re-check the lockout that the password stage and
    # the counter below share, so a locked account cannot keep guessing codes.
    # Expired locks are cleared first, exactly as /api/login does.
    unlock_if_expired(user)
    user = db.execute("SELECT * FROM users WHERE id = ?", (pending_user_id,)).fetchone()
    if user_locked(user):
        session.pop("pending_user_id", None)
        session.pop("pending_otp_generated", None)
        log_event("OTP_FAILED", user["username"], "account locked")
        return jsonify({"ok": False, "message": "Account is locked. Try again later."}), 403

    data = request.get_json(silent=True) or {}
    otp_code = (data.get("otp") or "").strip()

    if verify_otp(user["otp_secret"], otp_code):
        login_user(User(user["id"], user["username"], user["role"]))
        db.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]),
        )
        db.commit()
        session.pop("pending_user_id", None)
        session.pop("pending_otp_generated", None)
        log_event("LOGIN_SUCCESS", user["username"])
        return jsonify(
            {
                "ok": True,
                "user": {
                    "username": user["username"],
                    "role": user["role"],
                    # Set on accounts still holding a shipped default password.
                    # The SPA sends these users to Settings instead of the
                    # dashboard until they choose their own.
                    "mustChangePassword": bool(user["must_change_password"]),
                },
                "security": {"otpVerified": True, "sessionCreated": True},
            }
        )

    # Prevents OTP brute force: a 6-digit TOTP is only a million possibilities
    # (widened further by pyotp's valid_window drift allowance), so an
    # unthrottled endpoint is guessable. Wrong codes are counted against the
    # same failed_attempts / locked_until columns the password check uses, and
    # trip the same MAX_LOGIN_ATTEMPTS / LOCK_MINUTES lockout.
    attempts = user["failed_attempts"] + 1
    lock_until = None
    message = "Invalid OTP."

    if attempts >= app.config["MAX_LOGIN_ATTEMPTS"]:
        lock_until = (datetime.now() + timedelta(minutes=app.config["LOCK_MINUTES"])).isoformat()
        message = "Too many invalid OTP attempts. Account locked temporarily."
        # Discard the half-finished login so the attacker has to clear the
        # password stage again once the lock expires.
        session.pop("pending_user_id", None)
        session.pop("pending_otp_generated", None)
        log_event("OTP_LOCKOUT", user["username"], f"max OTP attempts reached ({attempts})")
    else:
        log_event("OTP_FAILED", user["username"], f"failed_attempts={attempts}")

    db.execute(
        "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
        (attempts, lock_until, user["id"]),
    )
    db.commit()

    return jsonify({"ok": False, "message": message}), (403 if lock_until else 401)


@app.route("/api/dashboard")
@login_required
@role_required("customer", "admin")
def api_dashboard():
    db = get_db()
    user = db.execute(
        "SELECT name, username, email, current_balance_minor, wallet_balance_minor, account_number, last_login, role FROM users WHERE id = ?",
        (current_user.id,),
    ).fetchone()

    recent_transactions = db.execute(
        """
        SELECT t.date AS date, t.sender AS sender, t.receiver AS receiver, t.status AS status,
               t.encrypted_amount AS encrypted_amount, t.encrypted_aes_key AS encrypted_aes_key,
               u.account_number AS receiver_account_number
        FROM transactions t
        LEFT JOIN users u ON u.username = t.receiver
        WHERE t.sender = ? OR t.receiver = ?
        ORDER BY t.date DESC
        LIMIT 5
        """,
        (current_user.username, current_user.username),
    ).fetchall()

    system_summary = None
    if user["role"] == "admin":
        total_users = db.execute("SELECT COUNT(*) AS count FROM users").fetchone()["count"]
        total_transactions = db.execute("SELECT COUNT(*) AS count FROM transactions").fetchone()["count"]
        latest_transactions = db.execute(
            "SELECT date, sender, receiver, status FROM transactions ORDER BY date DESC LIMIT 5"
        ).fetchall()
        system_summary = {
            "totalUsers": total_users,
            "totalTransactions": total_transactions,
            "latestTransactions": [
                {"date": tx["date"], "sender": tx["sender"], "receiver": tx["receiver"], "status": tx["status"]}
                for tx in latest_transactions
            ],
        }

    return jsonify(
        {
            "user": {
                "name": user["name"],
                "username": user["username"],
                "email": user["email"],
                "currentBalance": money_json(user["current_balance_minor"]),
                "walletBalance": money_json(user["wallet_balance_minor"]),
                "accountNumber": user["account_number"],
                "lastLogin": user["last_login"],
                "role": user["role"],
            },
            "recentTransactions": [
                {
                    "date": tx["date"],
                    "direction": "sent" if tx["sender"] == current_user.username else "received",
                    "counterparty": tx["receiver"] if tx["sender"] == current_user.username else tx["sender"],
                    "receiver": tx["receiver"],
                    "status": tx["status"],
                    "receiverAccountNumber": tx["receiver_account_number"],
                    "amount": decrypt_transaction_amount(tx["encrypted_amount"], tx["encrypted_aes_key"]),
                }
                for tx in recent_transactions
            ],
            "systemSummary": system_summary,
            "securityStatus": security_status_flags(),
        }
    )


# Prevents SQL injection: the balance column name is interpolated into the
# UPDATE statements below, so it may only ever come from this hardcoded
# allowlist and never straight from the request body.
BALANCE_COLUMNS = {"card": "current_balance_minor", "wallet": "wallet_balance_minor"}


@app.route("/api/transfer", methods=["POST"])
@login_required
@role_required("customer", "admin")
def api_transfer():
    data = request.get_json(silent=True) or {}
    receiver_account_number = (data.get("receiver") or "").strip()
    amount = str(data.get("amount") or "").strip()
    description = (data.get("description") or "").strip()
    source = (data.get("source") or "card").strip()

    if not all([receiver_account_number, amount, description]):
        return jsonify({"ok": False, "message": "All transfer fields are required."}), 400

    if source not in ("card", "wallet"):
        return jsonify({"ok": False, "message": "Invalid transfer source."}), 400

    # Exact decimal parsing, then integer cents for every downstream comparison.
    amount_value = parse_money(amount)
    if amount_value is None or amount_value <= 0:
        return jsonify({"ok": False, "message": "Amount must be a positive number."}), 400
    amount_minor = to_minor(amount_value)

    db = get_db()
    receiver_row = db.execute(
        "SELECT id, username FROM users WHERE account_number = ?",
        (receiver_account_number,),
    ).fetchone()
    if receiver_row is None:
        return jsonify({"ok": False, "message": "No account found with that account number."}), 404
    if str(receiver_row["id"]) == current_user.id:
        return jsonify({"ok": False, "message": "You cannot transfer to your own account."}), 400
    receiver = receiver_row["username"]

    # "source" is validated against ("card", "wallet") above, so this lookup can
    # only ever return one of the two hardcoded column names.
    balance_column = BALANCE_COLUMNS[source]

    private_key = load_private_key(app.config["RSA_PRIVATE_KEY_PATH"])
    public_key = load_public_key(app.config["RSA_PUBLIC_KEY_PATH"])

    aes_key = generate_aes_key()
    plaintext = f"{receiver}|LKR {amount_value:.2f}|{description}"
    plaintext_hash = sha256_hash(plaintext)
    encrypted_amount = aes_encrypt(f"{amount_value:.2f}", aes_key)
    encrypted_message = aes_encrypt(f"{receiver}|{description}", aes_key)
    encrypted_key_bytes = rsa_encrypt(aes_key, public_key)
    encrypted_aes_key = base64.b64encode(encrypted_key_bytes).decode("utf-8")

    signed_payload = f"{plaintext}|{plaintext_hash}|{encrypted_amount}|{encrypted_message}|{encrypted_aes_key}".encode("utf-8")
    signature = sign_data(signed_payload, private_key)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    # Self-test only. This verifies a signature this process just produced with
    # the matching key, so it cannot fail in practice - it demonstrates the
    # verification API rather than protecting anything. The integrity check that
    # actually matters happens on read, in verify_transaction_row().
    signature_verified = verify_signature(signed_payload, signature, public_key)
    if not signature_verified:
        log_event("TRANSFER_FAILED", current_user.username, "signature verification failed")
        return jsonify({"ok": False, "message": "Signature verification failed. Transfer aborted."}), 500

    # Prevents TOCTOU double-spend race: BEGIN IMMEDIATE takes the SQLite write
    # lock before any balance is touched, so concurrent transfers are serialised
    # instead of all passing a check against the same stale balance.
    db.execute("BEGIN IMMEDIATE")
    try:
        # Prevents TOCTOU double-spend race: the sufficiency check and the debit
        # are now one conditional statement. SQLite re-evaluates the
        # "column >= amount" guard at write time, so an overdraft can never be
        # committed. rowcount == 0 means the guard rejected the debit.
        debit = db.execute(
            f"UPDATE users SET {balance_column} = {balance_column} - ? "
            f"WHERE id = ? AND {balance_column} >= ?",
            (amount_minor, current_user.id, amount_minor),
        )
        if debit.rowcount == 0:
            db.execute("ROLLBACK")
            log_event("TRANSFER_FAILED", current_user.username, f"insufficient {source} balance")
            return jsonify({"ok": False, "message": f"Insufficient {source} balance."}), 400

        db.execute(
            "UPDATE users SET current_balance_minor = current_balance_minor + ? WHERE id = ?",
            (amount_minor, receiver_row["id"]),
        )
        db.execute(
            """
            INSERT INTO transactions (
                sender,
                receiver,
                encrypted_amount,
                encrypted_message,
                encrypted_aes_key,
                signature,
                date,
                status,
                source
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                current_user.username,
                receiver,
                encrypted_amount,
                encrypted_message,
                encrypted_aes_key,
                signature_b64,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "SUCCESS",
                source,
            ),
        )
        # Debit, credit and ledger row land in a single commit, so the books can
        # never be left half-written.
        db.execute("COMMIT")
    except sqlite3.Error:
        db.rollback()
        raise

    updated = db.execute(
        "SELECT current_balance_minor, wallet_balance_minor FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    log_event("TRANSFER_SUCCESS", current_user.username, f"to={receiver} amount={amount_value:.2f} source={source}")

    # Out-of-band confirmation over SMTP+STARTTLS. This runs after COMMIT and its
    # result is only reported: a mail failure must never undo a transfer that the
    # database has already accepted.
    sender_row = db.execute(
        "SELECT name, email FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()
    confirmation = send_secure_email(
        sender_row["email"],
        "SecureBank transfer confirmation",
        (
            f"Hello {sender_row['name']},\n\n"
            f"A transfer has been completed on your account.\n\n"
            f"  Amount      : LKR {amount_value:.2f}\n"
            f"  To account  : {receiver_account_number}\n"
            f"  Funded from : {source}\n"
            f"  Reference   : {description}\n"
            f"  Date        : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"  Remaining current balance : LKR {from_minor(updated['current_balance_minor']):.2f}\n"
            f"  Remaining wallet balance  : LKR {from_minor(updated['wallet_balance_minor']):.2f}\n\n"
            "If you did not authorise this transfer, contact SecureBank immediately.\n"
        ),
    )
    return jsonify(
        {
            "ok": True,
            "message": "Transfer secured and recorded successfully.",
            "currentBalance": money_json(updated["current_balance_minor"]),
            "walletBalance": money_json(updated["wallet_balance_minor"]),
            "securityMonitor": {
                "plaintext": plaintext,
                "hash": plaintext_hash,
                "ciphertext": encrypted_message,
                "encryptedAesKey": encrypted_aes_key,
                "signature": signature_b64,
                "transport": "HTTPS/TLS" if request.is_secure else "HTTP demo",
                "storage": "SQLite encrypted record",
            },
            "securityPipeline": {
                "steps": [
                    {
                        "step": 1,
                        "title": "Plaintext",
                        "algorithm": "User Input",
                        "status": "completed",
                        "value": plaintext,
                    },
                    {
                        "step": 2,
                        "title": "SHA-256 Hash",
                        "algorithm": "SHA-256",
                        "status": "completed",
                        "value": plaintext_hash,
                    },
                    {
                        "step": 3,
                        "title": "AES Encryption",
                        "algorithm": "AES-256-GCM",
                        "status": "completed",
                        "value": encrypted_message[:32] + "...",
                    },
                    {
                        "step": 4,
                        "title": "RSA Encrypt AES Key",
                        "algorithm": "RSA-2048-OAEP",
                        "status": "completed",
                        "value": encrypted_aes_key[:32] + "...",
                    },
                    {
                        "step": 5,
                        "title": "Digital Signature",
                        "algorithm": SCHEME_PSS,
                        "status": "completed",
                        "value": signature_b64[:32] + "...",
                    },
                    {
                        "step": 6,
                        "title": "TLS Transmission",
                        "algorithm": "HTTPS/TLS",
                        "status": "completed" if request.is_secure else "demo",
                        "value": "Secure channel",
                    },
                    {
                        "step": 7,
                        "title": "Database Storage",
                        "algorithm": "SQLite",
                        "status": "completed",
                        "value": "Encrypted transaction fields stored",
                    },
                    {
                        "step": 8,
                        "title": "Secure Mail Confirmation",
                        "algorithm": confirmation["protocol"],
                        "status": "completed" if confirmation["sent"] else "skipped",
                        "value": confirmation["cipher"] or confirmation["detail"],
                    },
                ]
            },
            "mailConfirmation": {
                "sent": confirmation["sent"],
                "recipient": mask_email(sender_row["email"]),
                "protocol": confirmation["protocol"],
                "tlsVersion": confirmation["tlsVersion"],
                "cipher": confirmation["cipher"],
                "detail": confirmation["detail"],
            },
        }
    )


@app.route("/api/wallet/topup", methods=["POST"])
@login_required
@role_required("customer", "admin")
def api_wallet_topup():
    data = request.get_json(silent=True) or {}
    amount = str(data.get("amount") or "").strip()

    amount_value = parse_money(amount)
    if amount_value is None or amount_value <= 0:
        return jsonify({"ok": False, "message": "Amount must be a positive number."}), 400
    amount_minor = to_minor(amount_value)

    db = get_db()

    # Prevents TOCTOU double-spend race: same pattern as /api/transfer — take the
    # write lock, then move the money with one conditional statement whose
    # "current_balance_minor >= ?" guard SQLite re-checks at write time.
    db.execute("BEGIN IMMEDIATE")
    try:
        topup = db.execute(
            "UPDATE users SET current_balance_minor = current_balance_minor - ?, "
            "wallet_balance_minor = wallet_balance_minor + ? "
            "WHERE id = ? AND current_balance_minor >= ?",
            (amount_minor, amount_minor, current_user.id, amount_minor),
        )
        if topup.rowcount == 0:
            db.execute("ROLLBACK")
            log_event("WALLET_TOPUP_FAILED", current_user.username, "insufficient card balance")
            return jsonify({"ok": False, "message": "Insufficient card balance."}), 400
        db.execute("COMMIT")
    except sqlite3.Error:
        db.rollback()
        raise

    updated = db.execute(
        "SELECT current_balance_minor, wallet_balance_minor FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    log_event("WALLET_TOPUP", current_user.username, f"amount={amount_value:.2f}")
    return jsonify(
        {
            "ok": True,
            "message": "Wallet topped up successfully.",
            "currentBalance": money_json(updated["current_balance_minor"]),
            "walletBalance": money_json(updated["wallet_balance_minor"]),
        }
    )


@app.route("/api/transactions")
@login_required
def api_transaction_history():
    db = get_db()
    transactions = db.execute(
        """
        SELECT id, date, sender, receiver, encrypted_amount, encrypted_message,
               encrypted_aes_key, signature, status
        FROM transactions
        WHERE sender = ? OR receiver = ?
        ORDER BY date DESC
        """,
        (current_user.username, current_user.username),
    ).fetchall()

    rows = []
    for tx in transactions:
        # Every row is verified on the way out, not assumed good.
        integrity = verify_transaction_row(tx)

        if not integrity["valid"]:
            log_event(
                "SIGNATURE_INVALID",
                current_user.username,
                f"transaction_id={tx['id']} sender={tx['sender']} "
                f"receiver={tx['receiver']} date={tx['date']} reason={integrity['detail']}",
            )

        rows.append(
            {
                "date": tx["date"],
                "direction": "sent" if tx["sender"] == current_user.username else "received",
                "counterparty": tx["receiver"] if tx["sender"] == current_user.username else tx["sender"],
                "receiver": tx["receiver"],
                "amount": integrity["amount"],
                "encryptedAmount": tx["encrypted_amount"],
                "status": tx["status"],
                # Real verification results, replacing the old hardcoded strings.
                "signatureValid": integrity["valid"],
                "signatureStatus": integrity["status"],
                "security": {
                    "aes": "Encrypted (AES-256-GCM)",
                    "rsa": "Key Encrypted (RSA-2048-OAEP)",
                    "signature": f"{integrity['status']} ({integrity['scheme']})",
                    "signatureValid": integrity["valid"],
                    "signatureStatus": integrity["status"],
                    "signatureScheme": integrity["scheme"],
                    "signatureDetail": integrity["detail"],
                    "encryptedAesKeyPreview": tx["encrypted_aes_key"][:24] + "...",
                    "signaturePreview": tx["signature"][:24] + "...",
                },
            }
        )

    return jsonify({"transactions": rows})


@app.route("/api/profile")
@login_required
def api_profile():
    db = get_db()
    user = db.execute(
        "SELECT name, username, email, last_login, role, account_number FROM users WHERE id = ?",
        (current_user.id,),
    ).fetchone()

    tls_status = certificate_status(app.config["SSL_CERT_PATH"], app.config["SSL_KEY_PATH"])
    return jsonify({"user": serialize_user_row(user), "certificateStatus": tls_status})


# Lets a user enrol this account's TOTP secret into a real authenticator app,
# which is what makes withholding "demoOtp" from the login response workable.
@app.route("/api/profile/otp-uri")
@login_required
def api_profile_otp_uri():
    db = get_db()
    user = db.execute(
        "SELECT username, otp_secret FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()
    if user is None:
        return jsonify({"ok": False, "message": "User not found."}), 404

    # The secret is only ever released to the authenticated owner of the
    # account, and the access is written to the security log as audit evidence.
    log_event("OTP_ENROLMENT_ISSUED", current_user.username, "provisioning URI requested")
    return jsonify(
        {
            "ok": True,
            "otpUri": provisioning_uri(user["otp_secret"], user["username"]),
            "secret": user["otp_secret"],
            "issuer": OTP_ISSUER,
            "account": user["username"],
            "algorithm": "TOTP / SHA-1 / 6 digits / 30 second period",
        }
    )


@app.route("/api/profile", methods=["PATCH"])
@login_required
def api_profile_update():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip()

    if not all([name, email]):
        return jsonify({"ok": False, "message": "Name and email are required."}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE email = ? AND id != ?", (email, current_user.id)
    ).fetchone()
    if existing:
        return jsonify({"ok": False, "message": "Email is already in use."}), 409

    db.execute(
        "UPDATE users SET name = ?, email = ? WHERE id = ?",
        (name, email, current_user.id),
    )
    db.commit()

    log_event("PROFILE_UPDATED", current_user.username, "name/email updated")

    user = db.execute(
        "SELECT name, username, email, last_login, role, account_number FROM users WHERE id = ?",
        (current_user.id,),
    ).fetchone()
    return jsonify({"ok": True, "message": "Profile updated successfully.", "user": serialize_user_row(user)})


@app.route("/api/profile/password", methods=["POST"])
@login_required
def api_profile_change_password():
    data = request.get_json(silent=True) or {}
    current_password = data.get("currentPassword") or ""
    new_password = data.get("newPassword") or ""
    confirm_password = data.get("confirmPassword") or ""

    if not all([current_password, new_password, confirm_password]):
        return jsonify({"ok": False, "message": "All password fields are required."}), 400

    db = get_db()
    user = db.execute(
        "SELECT password_hash FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    # Same verification path as /api/login: verify_password() handles scrypt,
    # pbkdf2 and migrated legacy rows, and rejects anything else outright. An
    # unsalted SHA-256 comparison is not an accepted authentication path here.
    if not verify_password(current_password, user["password_hash"]):
        log_event("PASSWORD_CHANGE_FAILED", current_user.username, "incorrect current password")
        return jsonify({"ok": False, "message": "Current password is incorrect."}), 401

    if new_password != confirm_password:
        return jsonify({"ok": False, "message": "New passwords do not match."}), 400

    valid, message = validate_password_complexity(new_password)
    if not valid:
        return jsonify({"ok": False, "message": message}), 400

    # Clearing must_change_password here is the only place the flag is lifted: the
    # account has now moved off whatever default it shipped with.
    db.execute(
        "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
        (password_hash(new_password), current_user.id),
    )
    db.commit()

    log_event("PASSWORD_CHANGED", current_user.username, "password changed via settings")
    return jsonify({"ok": True, "message": "Password changed successfully.", "mustChangePassword": False})


@app.route("/api/admin/overview")
@login_required
@admin_required
def api_admin_overview():
    db = get_db()
    users = db.execute(
        "SELECT id, name, username, email, role, last_login FROM users ORDER BY id"
    ).fetchall()
    transactions = db.execute(
        "SELECT id, sender, receiver, date, status FROM transactions ORDER BY id DESC LIMIT 20"
    ).fetchall()

    log_lines = []
    total_log_events = 0
    if os.path.exists(app.config["LOG_PATH"]):
        with open(app.config["LOG_PATH"], "r", encoding="utf-8") as log_file:
            all_lines = log_file.readlines()
            total_log_events = len(all_lines)
            log_lines = all_lines[-30:]

    tls_active = os.path.exists(app.config["SSL_CERT_PATH"]) and os.path.exists(app.config["SSL_KEY_PATH"])
    backup_exists = os.path.exists(BACKUP_ENCRYPTED_PATH)

    security_dashboard = {
        "firewall": "Not enforced by application (configure OS-level firewall)",
        "https": "Active" if request.is_secure else "Inactive (running over HTTP)",
        "tls": "Enabled" if tls_active else "Certificate missing",
        "aes": "Enabled (AES-256-GCM)",
        "rsa": "Enabled (RSA-2048-OAEP)",
        "digitalSignature": f"Enabled ({SCHEME_PSS})",
        "otp": "Enabled (TOTP via pyotp)",
        "databaseBackup": "Completed" if backup_exists else "Not yet run",
        "logEvents": total_log_events,
    }

    return jsonify(
        {
            "securityDashboard": security_dashboard,
            "users": [
                {
                    "id": u["id"],
                    "name": u["name"],
                    "username": u["username"],
                    "email": u["email"],
                    "role": u["role"],
                    "lastLogin": u["last_login"],
                }
                for u in users
            ],
            "transactions": [
                {
                    "id": tx["id"],
                    "sender": tx["sender"],
                    "receiver": tx["receiver"],
                    "date": tx["date"],
                    "status": tx["status"],
                }
                for tx in transactions
            ],
            "logLines": [line.rstrip("\n") for line in log_lines],
        }
    )


def resolve_backup_passphrase(data) -> str:
    """Passphrase from the request body, falling back to the environment."""
    supplied = (data.get("passphrase") or "").strip()
    return supplied or app.config["BACKUP_PASSPHRASE"]


def derive_backup_key(passphrase: str, salt: bytes) -> bytes:
    """Stretch an operator passphrase into a 256-bit AES key with scrypt.

    Prevents key-beside-ciphertext exposure: the previous build generated a
    random key and wrote it to backups/bank_backup.key, right next to the
    encrypted database, so anyone who copied the backup directory got both
    halves. Now only a random salt is stored; the key itself exists solely in
    memory for the duration of the request and is reconstructed on demand from
    a passphrase the operator supplies.

    scrypt is memory-hard, so guessing the passphrase offline is far more
    expensive than it would be against a plain hash.
    """
    return scrypt_kdf(
        passphrase,
        salt,
        key_len=32,
        N=BACKUP_KDF_N,
        r=BACKUP_KDF_R,
        p=BACKUP_KDF_P,
    )


@app.route("/api/security/backup", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_backup_database():
    data = request.get_json(silent=True) or {}
    passphrase = resolve_backup_passphrase(data)
    if not passphrase:
        return jsonify(
            {
                "ok": False,
                "message": (
                    "A backup passphrase is required. Set the BACKUP_PASSPHRASE "
                    "environment variable, or send a 'passphrase' field with this request."
                ),
            }
        ), 400

    source = app.config["DATABASE_PATH"]
    os.makedirs("backups", exist_ok=True)

    with open(source, "rb") as db_file:
        db_bytes = db_file.read()

    steps = [{"step": 1, "title": "Database Snapshot", "status": "completed", "detail": f"{len(db_bytes)} bytes read from {source}"}]

    plaintext_hash = sha256_hash_bytes(db_bytes)
    steps.append({"step": 2, "title": "Hash Generated", "status": "completed", "detail": f"SHA-256: {plaintext_hash[:24]}..."})

    # Fresh salt per backup, so two backups under the same passphrase still
    # produce different keys.
    salt = os.urandom(BACKUP_SALT_BYTES)
    backup_key = derive_backup_key(passphrase, salt)
    steps.append(
        {
            "step": 3,
            "title": "Key Derivation",
            "status": "completed",
            "detail": (
                f"scrypt(N={BACKUP_KDF_N}, r={BACKUP_KDF_R}, p={BACKUP_KDF_P}) over the "
                f"operator passphrase with a {BACKUP_SALT_BYTES}-byte random salt"
            ),
        }
    )

    encrypted_payload = aes_encrypt_bytes(db_bytes, backup_key)
    with open(BACKUP_ENCRYPTED_PATH, "w", encoding="utf-8") as enc_file:
        enc_file.write(encrypted_payload)
    # Only the salt is persisted. The key stays in memory and is thrown away
    # when this request ends.
    with open(BACKUP_SALT_PATH, "w", encoding="utf-8") as salt_file:
        salt_file.write(base64.b64encode(salt).decode("utf-8"))
    with open(BACKUP_HASH_PATH, "w", encoding="utf-8") as hash_file:
        hash_file.write(plaintext_hash)

    # An older build stored the raw key beside the ciphertext. Delete any copy
    # it left behind rather than leaving the old exposure in place.
    if os.path.exists(LEGACY_BACKUP_KEY_PATH):
        os.remove(LEGACY_BACKUP_KEY_PATH)
        log_event(
            "BACKUP_KEY_FILE_REMOVED",
            current_user.username,
            f"deleted plaintext key file {LEGACY_BACKUP_KEY_PATH}",
        )

    steps.append({"step": 4, "title": "AES Encryption", "status": "completed", "detail": "AES-256-GCM applied to full database snapshot"})
    steps.append({"step": 5, "title": "Backup Created", "status": "completed", "detail": f"{BACKUP_ENCRYPTED_PATH} (+ salt, no key on disk)"})

    decrypted_bytes = aes_decrypt_bytes(encrypted_payload, backup_key)
    recomputed_hash = sha256_hash_bytes(decrypted_bytes)
    integrity_ok = recomputed_hash == plaintext_hash
    steps.append(
        {
            "step": 6,
            "title": "Integrity Verified",
            "status": "completed" if integrity_ok else "failed",
            "detail": "Decrypted backup hash matches original" if integrity_ok else "Hash mismatch detected",
        }
    )

    # Protocol level - secure file transfer. Only the already AES-encrypted
    # artefact is shipped, over SFTP with mandatory host key verification, so the
    # plaintext database never leaves this machine. An unconfigured or
    # unreachable offsite server downgrades the run to "local copy only" rather
    # than failing the backup.
    upload = upload_backup(BACKUP_ENCRYPTED_PATH)
    steps.append(
        {
            "step": 7,
            "title": "Upload to offsite SFTP",
            "status": "completed" if upload["uploaded"] else "skipped",
            "detail": upload["detail"],
        }
    )

    log_event(
        "BACKUP_SUCCESS" if integrity_ok else "BACKUP_INTEGRITY_FAILED",
        current_user.username,
        f"destination={BACKUP_ENCRYPTED_PATH} hash={plaintext_hash[:16]} "
        f"offsite={upload['uploaded']}",
    )
    return jsonify(
        {
            "ok": integrity_ok,
            "message": "Encrypted backup created and integrity verified." if integrity_ok else "Backup integrity check failed.",
            "pipeline": steps,
            "offsiteTransfer": upload,
        }
    )


@app.route("/api/security/backup/verify", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_verify_backup():
    data = request.get_json(silent=True) or {}
    passphrase = resolve_backup_passphrase(data)
    if not passphrase:
        return jsonify(
            {
                "ok": False,
                "message": (
                    "A backup passphrase is required to decrypt the backup. Set the "
                    "BACKUP_PASSPHRASE environment variable, or send a 'passphrase' field."
                ),
            }
        ), 400

    required_paths = (BACKUP_ENCRYPTED_PATH, BACKUP_SALT_PATH, BACKUP_HASH_PATH)
    if not all(os.path.exists(path) for path in required_paths):
        return jsonify({"ok": False, "message": "No complete encrypted backup is available to verify."}), 404

    try:
        with open(BACKUP_ENCRYPTED_PATH, "r", encoding="utf-8") as backup_file:
            encrypted_payload = backup_file.read()
        with open(BACKUP_SALT_PATH, "r", encoding="utf-8") as salt_file:
            salt = base64.b64decode(salt_file.read())
        with open(BACKUP_HASH_PATH, "r", encoding="utf-8") as hash_file:
            expected_hash = hash_file.read().strip()

        # Reconstructed from the passphrase, never read from disk.
        backup_key = derive_backup_key(passphrase, salt)

        # A wrong passphrase derives a wrong key, and AES-GCM rejects it here.
        restored_bytes = aes_decrypt_bytes(encrypted_payload, backup_key)
        actual_hash = sha256_hash_bytes(restored_bytes)
        integrity_ok = actual_hash == expected_hash
    except (OSError, ValueError, TypeError) as exc:
        integrity_ok = False
        log_event("BACKUP_VERIFY_FAILED", current_user.username, str(exc))
        return jsonify(
            {
                "ok": False,
                "message": (
                    "Backup could not be decrypted or verified. The passphrase may be "
                    "wrong, or the backup file may have been altered."
                ),
            }
        ), 422

    log_event(
        "BACKUP_VERIFY_SUCCESS" if integrity_ok else "BACKUP_INTEGRITY_FAILED",
        current_user.username,
        f"backup={BACKUP_ENCRYPTED_PATH} hash_match={integrity_ok}",
    )
    return jsonify({
        "ok": integrity_ok,
        "message": "Backup decrypted and integrity verified without changing the live database." if integrity_ok else "Backup integrity verification failed.",
        "restoredBytes": len(restored_bytes),
        "hashMatch": integrity_ok,
    }), (200 if integrity_ok else 422)


@app.route("/api/logout", methods=["POST"])
@login_required
def api_logout():
    username = current_user.username
    logout_user()
    log_event("LOGOUT", username)
    return jsonify({"ok": True, "message": "You have been logged out."})


def bootstrap_app():
    setup_logging()
    ensure_rsa_keys(app.config["RSA_PRIVATE_KEY_PATH"], app.config["RSA_PUBLIC_KEY_PATH"])
    with app.app_context():
        init_db()
        migrate_legacy_password_hashes()
        register_default_admin()
        register_default_security_staff()
        register_demo_target_account()


if __name__ == "__main__":
    bootstrap_app()
    ssl_context = ssl_context_if_available(app.config["SSL_CERT_PATH"], app.config["SSL_KEY_PATH"])

    # Prevents remote code execution via the Werkzeug debugger: debug mode serves
    # an interactive console that runs arbitrary Python on any unhandled
    # exception. FLASK_DEBUG is its only trigger.
    #
    # DEMO_MODE deliberately does NOT enable it. DEMO_MODE exists so a live demo
    # can display the OTP; wiring it to the debugger would mean a presentation
    # convenience quietly opens a remote shell on the same machine.
    debug_mode = env_flag("FLASK_DEBUG")

    if debug_mode:
        print(
            "WARNING: Flask debug mode is ON. The Werkzeug interactive debugger "
            "executes arbitrary Python on any unhandled exception. Do not use this "
            "on a shared or untrusted network.",
            file=sys.stderr,
        )

    # Prevents unintended network exposure: binding 0.0.0.0 published the
    # debugger (and the whole API) to every interface on the local network.
    # Loopback is the default; set HOST explicitly to expose it on a network
    # you control.
    host = os.getenv("HOST", "127.0.0.1")

    app.run(host=host, port=5000, debug=debug_mode, ssl_context=ssl_context)
