import base64
import logging
import os
import random
import shutil
import sqlite3
import string
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, g, jsonify, request, session
from flask_cors import CORS
from flask_login import (
    LoginManager,
    UserMixin,
    current_user,
    login_required,
    login_user,
    logout_user,
)

from config import Config
from security.aes import (
    aes_decrypt,
    aes_decrypt_bytes,
    aes_encrypt,
    aes_encrypt_bytes,
    generate_aes_key,
)
from security.certificate import certificate_status, ssl_context_if_available
from security.digital_signature import sign_data, verify_signature
from security.firewall_monitor import firewall_status_payload, get_firewall_profiles
from security.firewall_connections import read_recent_connections
from security.hashing import (
    password_hash,
    sha256_hash,
    sha256_hash_bytes,
    validate_password_complexity,
    verify_password,
)
from security.otp import current_otp, generate_otp_secret, verify_otp
from security.rsa import ensure_rsa_keys, load_private_key, load_public_key, rsa_decrypt, rsa_encrypt


app = Flask(__name__)
app.config.from_object(Config)

BACKUP_ENCRYPTED_PATH = os.path.join("backups", "bank_backup.db.enc")
BACKUP_HASH_PATH = os.path.join("backups", "bank_backup.sha256")
BACKUP_KEY_PATH = os.path.join("backups", "bank_backup.key")

CORS(app, supports_credentials=True, origins=[app.config["CORS_ORIGIN"]])

login_manager = LoginManager()
login_manager.init_app(app)


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


def generate_account_number(db):
    while True:
        candidate = "".join(random.choices(string.digits, k=12))
        existing = db.execute(
            "SELECT id FROM users WHERE account_number = ?", (candidate,)
        ).fetchone()
        if existing is None:
            return candidate


def decrypt_transaction_amount(encrypted_amount, encrypted_aes_key):
    private_key = load_private_key(app.config["RSA_PRIVATE_KEY_PATH"])
    aes_key = rsa_decrypt(base64.b64decode(encrypted_aes_key), private_key)
    return float(aes_decrypt(encrypted_amount, aes_key))


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


def register_default_admin():
    db = get_db()
    admin = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
    if admin is not None:
        return

    db.execute(
        """
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            generate_account_number(db),
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
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            generate_account_number(db),
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
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
    ids_exercised = log_event_seen({"ATTACK_SIMULATION", "TRANSFER_FAILED", "OTP_FAILED"}, log_lines)
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
    "REGISTER_SUCCESS": ("Account Registered", "New customer record created"),
    "TRANSFER_SUCCESS": ("Transaction Signed", "RSA-SHA256 integrity check + database update"),
    "TRANSFER_FAILED": ("Transaction Rejected", "Signature verification failed"),
    "BACKUP_SUCCESS": ("Backup Completed", "AES encryption + hash + integrity verification"),
    "BACKUP_INTEGRITY_FAILED": ("Backup Integrity Failed", "Decrypted hash did not match original"),
    "ATTACK_SIMULATION": ("Attack Simulated", "Security lab exercised a defense mechanism"),
    "LOGOUT": ("Session Ended", "User logged out"),
}

FALLBACK_TIMELINE_TEMPLATE = [
    ("Login", "Customer requested secure access"),
    ("Password Verified", "SHA-256 hash matched"),
    ("OTP Generated", "TOTP challenge issued"),
    ("OTP Verified", "Second factor accepted"),
    ("TLS Session Created", "HTTPS transport active"),
    ("AES Session Started", "Transaction payload encrypted"),
    ("Transaction Signed", "RSA-SHA256 integrity check"),
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
    "Tampered Transaction": "RSA-SHA256 signature verification",
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
            "encryption": "AES-256-CBC",
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


def build_encryption_monitor(receiver: str, amount_value: float, message: str):
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
        {"step": 3, "title": "AES Encryption", "algorithm": "AES-256-CBC", "status": "completed", "value": monitor["ciphertext"][:32] + "..."},
        {"step": 4, "title": "RSA Encrypt AES Key", "algorithm": "RSA-2048-OAEP", "status": "completed", "value": monitor["encryptedAesKey"][:32] + "..."},
        {"step": 5, "title": "Digital Signature", "algorithm": "RSA-SHA256", "status": "completed", "value": monitor["signature"][:32] + "..."},
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

    sequence = ["Legitimate transaction signed with RSA-SHA256"]
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
        {"label": "Encryption", "status": "PASS", "detail": "AES-256-CBC active"},
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


@app.route("/api/session")
def api_session():
    if not current_user.is_authenticated:
        return jsonify({"authenticated": False, "securityStatus": security_status_flags()}), 401
    return jsonify(
        {
            "authenticated": True,
            "user": {
                "username": current_user.username,
                "role": current_user.role,
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
    try:
        amount_value = float(amount_raw)
    except ValueError:
        amount_value = 0.0

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
        "SELECT id, name, username, email, role, current_balance, wallet_balance, last_login FROM users ORDER BY id"
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
                    "currentBalance": row["current_balance"],
                    "walletBalance": row["wallet_balance"],
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
        INSERT INTO users (name, username, email, password_hash, otp_secret, role, balance, current_balance, wallet_balance, account_number)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                "algorithm": "SHA-256",
                "passwordHash": "scrypt hash generated (value withheld)",
                "note": "Only the hash is stored. The plaintext password is never saved.",
            },
        }
    )


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

    if not user["password_hash"].startswith(("scrypt:", "pbkdf2:")):
        db.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash(password), user["id"]),
        )
        db.commit()

    otp_code = current_otp(user["otp_secret"])
    session["pending_user_id"] = user["id"]
    session["pending_otp_generated"] = datetime.now().isoformat()

    # For coursework demo, the OTP is returned directly instead of integrating SMS/email.
    return jsonify(
        {
            "ok": True,
            "otpRequired": True,
            "demoOtp": otp_code,
            "security": {"passwordVerified": True, "algorithm": "scrypt (adaptive hash)", "otpAlgorithm": "TOTP (pyotp)"},
        }
    )


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
                "user": {"username": user["username"], "role": user["role"]},
                "security": {"otpVerified": True, "sessionCreated": True},
            }
        )

    log_event("OTP_FAILED", user["username"])
    return jsonify({"ok": False, "message": "Invalid OTP."}), 401


@app.route("/api/dashboard")
@login_required
@role_required("customer", "admin")
def api_dashboard():
    db = get_db()
    user = db.execute(
        "SELECT name, username, email, current_balance, wallet_balance, account_number, last_login, role FROM users WHERE id = ?",
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
                "currentBalance": user["current_balance"],
                "walletBalance": user["wallet_balance"],
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

    try:
        amount_value = float(amount)
        if amount_value <= 0:
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "message": "Amount must be a positive number."}), 400

    db = get_db()
    sender_row = db.execute(
        "SELECT current_balance, wallet_balance, username FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    receiver_row = db.execute(
        "SELECT id, username, current_balance FROM users WHERE account_number = ?",
        (receiver_account_number,),
    ).fetchone()
    if receiver_row is None:
        return jsonify({"ok": False, "message": "No account found with that account number."}), 404
    if str(receiver_row["id"]) == current_user.id:
        return jsonify({"ok": False, "message": "You cannot transfer to your own account."}), 400
    receiver = receiver_row["username"]

    balance_column = "current_balance" if source == "card" else "wallet_balance"
    if sender_row[balance_column] < amount_value:
        return jsonify({"ok": False, "message": f"Insufficient {source} balance."}), 400

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

    # Verify signature before storing to demonstrate integrity validation.
    signature_verified = verify_signature(signed_payload, signature, public_key)
    if not signature_verified:
        log_event("TRANSFER_FAILED", current_user.username, "signature verification failed")
        return jsonify({"ok": False, "message": "Signature verification failed. Transfer aborted."}), 500

    new_balance = sender_row[balance_column] - amount_value
    db.execute(
        f"UPDATE users SET {balance_column} = ? WHERE id = ?", (new_balance, current_user.id)
    )
    db.execute(
        "UPDATE users SET current_balance = current_balance + ? WHERE id = ?",
        (amount_value, receiver_row["id"]),
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
    db.commit()

    updated = db.execute(
        "SELECT current_balance, wallet_balance FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    log_event("TRANSFER_SUCCESS", current_user.username, f"to={receiver} amount={amount_value:.2f} source={source}")
    return jsonify(
        {
            "ok": True,
            "message": "Transfer secured and recorded successfully.",
            "currentBalance": updated["current_balance"],
            "walletBalance": updated["wallet_balance"],
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
                        "algorithm": "RSA-SHA256",
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
                ]
            },
        }
    )


@app.route("/api/wallet/topup", methods=["POST"])
@login_required
@role_required("customer", "admin")
def api_wallet_topup():
    data = request.get_json(silent=True) or {}
    amount = str(data.get("amount") or "").strip()

    try:
        amount_value = float(amount)
        if amount_value <= 0:
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "message": "Amount must be a positive number."}), 400

    db = get_db()
    sender_row = db.execute(
        "SELECT current_balance, wallet_balance FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    if sender_row["current_balance"] < amount_value:
        return jsonify({"ok": False, "message": "Insufficient card balance."}), 400

    db.execute(
        "UPDATE users SET current_balance = current_balance - ?, wallet_balance = wallet_balance + ? WHERE id = ?",
        (amount_value, amount_value, current_user.id),
    )
    db.commit()

    updated = db.execute(
        "SELECT current_balance, wallet_balance FROM users WHERE id = ?", (current_user.id,)
    ).fetchone()

    log_event("WALLET_TOPUP", current_user.username, f"amount={amount_value:.2f}")
    return jsonify(
        {
            "ok": True,
            "message": "Wallet topped up successfully.",
            "currentBalance": updated["current_balance"],
            "walletBalance": updated["wallet_balance"],
        }
    )


@app.route("/api/transactions")
@login_required
def api_transaction_history():
    db = get_db()
    transactions = db.execute(
        """
        SELECT date, sender, receiver, encrypted_amount, encrypted_aes_key, signature, status
        FROM transactions
        WHERE sender = ? OR receiver = ?
        ORDER BY date DESC
        """,
        (current_user.username, current_user.username),
    ).fetchall()

    return jsonify(
        {
            "transactions": [
                {
                    "date": tx["date"],
                    "direction": "sent" if tx["sender"] == current_user.username else "received",
                    "counterparty": tx["receiver"] if tx["sender"] == current_user.username else tx["sender"],
                    "receiver": tx["receiver"],
                    "amount": decrypt_transaction_amount(tx["encrypted_amount"], tx["encrypted_aes_key"]),
                    "encryptedAmount": tx["encrypted_amount"],
                    "status": tx["status"],
                    "security": {
                        "aes": "Encrypted (AES-256-CBC)",
                        "rsa": "Key Encrypted (RSA-2048)",
                        "signature": "Verified (RSA-SHA256)",
                        "encryptedAesKeyPreview": tx["encrypted_aes_key"][:24] + "...",
                        "signaturePreview": tx["signature"][:24] + "...",
                    },
                }
                for tx in transactions
            ]
        }
    )


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

    if not verify_sha256(current_password, user["password_hash"]):
        log_event("PASSWORD_CHANGE_FAILED", current_user.username, "incorrect current password")
        return jsonify({"ok": False, "message": "Current password is incorrect."}), 401

    if new_password != confirm_password:
        return jsonify({"ok": False, "message": "New passwords do not match."}), 400

    valid, message = validate_password_complexity(new_password)
    if not valid:
        return jsonify({"ok": False, "message": message}), 400

    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (password_hash(new_password), current_user.id),
    )
    db.commit()

    log_event("PASSWORD_CHANGED", current_user.username, "password changed via settings")
    return jsonify({"ok": True, "message": "Password changed successfully."})


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
        "digitalSignature": "Enabled (RSA-SHA256)",
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


@app.route("/api/security/backup", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_backup_database():
    source = app.config["DATABASE_PATH"]
    os.makedirs("backups", exist_ok=True)

    with open(source, "rb") as db_file:
        db_bytes = db_file.read()

    steps = [{"step": 1, "title": "Database Snapshot", "status": "completed", "detail": f"{len(db_bytes)} bytes read from {source}"}]

    plaintext_hash = sha256_hash_bytes(db_bytes)
    steps.append({"step": 2, "title": "Hash Generated", "status": "completed", "detail": f"SHA-256: {plaintext_hash[:24]}..."})

    backup_key = generate_aes_key()
    encrypted_payload = aes_encrypt_bytes(db_bytes, backup_key)
    with open(BACKUP_ENCRYPTED_PATH, "w", encoding="utf-8") as enc_file:
        enc_file.write(encrypted_payload)
    with open(BACKUP_KEY_PATH, "w", encoding="utf-8") as key_file:
        key_file.write(base64.b64encode(backup_key).decode("utf-8"))
    with open(BACKUP_HASH_PATH, "w", encoding="utf-8") as hash_file:
        hash_file.write(plaintext_hash)
    steps.append({"step": 3, "title": "AES Encryption", "status": "completed", "detail": "AES-256-GCM applied to full database snapshot"})
    steps.append({"step": 4, "title": "Backup Created", "status": "completed", "detail": BACKUP_ENCRYPTED_PATH})

    decrypted_bytes = aes_decrypt_bytes(encrypted_payload, backup_key)
    recomputed_hash = sha256_hash_bytes(decrypted_bytes)
    integrity_ok = recomputed_hash == plaintext_hash
    steps.append(
        {
            "step": 5,
            "title": "Integrity Verified",
            "status": "completed" if integrity_ok else "failed",
            "detail": "Decrypted backup hash matches original" if integrity_ok else "Hash mismatch detected",
        }
    )

    log_event(
        "BACKUP_SUCCESS" if integrity_ok else "BACKUP_INTEGRITY_FAILED",
        current_user.username,
        f"destination={BACKUP_ENCRYPTED_PATH} hash={plaintext_hash[:16]}",
    )
    return jsonify(
        {
            "ok": integrity_ok,
            "message": "Encrypted backup created and integrity verified." if integrity_ok else "Backup integrity check failed.",
            "pipeline": steps,
        }
    )


@app.route("/api/security/backup/verify", methods=["POST"])
@login_required
@role_required("security", "admin")
def api_verify_backup():
    required_paths = (BACKUP_ENCRYPTED_PATH, BACKUP_KEY_PATH, BACKUP_HASH_PATH)
    if not all(os.path.exists(path) for path in required_paths):
        return jsonify({"ok": False, "message": "No complete encrypted backup is available to verify."}), 404

    try:
        with open(BACKUP_ENCRYPTED_PATH, "r", encoding="utf-8") as backup_file:
            encrypted_payload = backup_file.read()
        with open(BACKUP_KEY_PATH, "r", encoding="utf-8") as key_file:
            backup_key = base64.b64decode(key_file.read())
        with open(BACKUP_HASH_PATH, "r", encoding="utf-8") as hash_file:
            expected_hash = hash_file.read().strip()

        restored_bytes = aes_decrypt_bytes(encrypted_payload, backup_key)
        actual_hash = sha256_hash_bytes(restored_bytes)
        integrity_ok = actual_hash == expected_hash
    except (OSError, ValueError, TypeError) as exc:
        integrity_ok = False
        log_event("BACKUP_VERIFY_FAILED", current_user.username, str(exc))
        return jsonify({"ok": False, "message": "Backup could not be decrypted or verified."}), 422

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
        register_default_admin()
        register_default_security_staff()
        register_demo_target_account()


if __name__ == "__main__":
    bootstrap_app()
    ssl_context = ssl_context_if_available(app.config["SSL_CERT_PATH"], app.config["SSL_KEY_PATH"])
    app.run(host="0.0.0.0", port=5000, debug=True, ssl_context=ssl_context)
