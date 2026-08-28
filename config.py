import os
import secrets


def env_flag(name: str, default: str = "false") -> bool:
    """Read a boolean-style environment variable ("1", "true", "yes", "on")."""
    return os.getenv(name, default).strip().lower() in ("1", "true", "yes", "on")


def load_secret_key() -> str:
    """Return the key Flask uses to sign session cookies.

    Resolved in this order:
      1. The SECRET_KEY environment variable, which is what a real deployment
         sets and what a container or CI secret store would inject.
      2. A cryptographically random key generated on first run and persisted
         to .secret_key (gitignored) so sessions survive a restart.

    Prevents session forgery: there is deliberately no hardcoded fallback.
    A default like "dev-secret-change-me" is published in the repository, so
    anyone who read the source could sign a cookie for any account - including
    admin - without ever knowing a password.
    """
    from_environment = os.getenv("SECRET_KEY", "").strip()
    if from_environment:
        return from_environment

    key_path = os.getenv("SECRET_KEY_PATH", ".secret_key")
    if os.path.exists(key_path):
        with open(key_path, encoding="utf-8") as key_file:
            stored = key_file.read().strip()
        if stored:
            return stored

    # 32 bytes from the OS CSPRNG, written once and reused on later runs.
    generated = secrets.token_hex(32)
    with open(key_path, "w", encoding="utf-8") as key_file:
        key_file.write(generated)
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return generated


class Config:
    SECRET_KEY = load_secret_key()
    DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join("database", "bank.db"))
    LOG_PATH = os.getenv("LOG_PATH", os.path.join("logs", "security.log"))

    # Authentication and account security controls
    MAX_LOGIN_ATTEMPTS = 5
    LOCK_MINUTES = 10
    SESSION_TIMEOUT_SECONDS = 20 * 60

    # Demo mode. When True the login response echoes the live TOTP code so the
    # coursework demo can be walked through without an authenticator app.
    # Defaults to False: handing the second factor to whoever just passed the
    # first factor would make MFA decorative.
    DEMO_MODE = env_flag("DEMO_MODE")

    # SSL certificate paths for local HTTPS demo
    SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "cert.pem")
    SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", "key.pem")

    # Cryptographic key locations
    RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH", os.path.join("security", "rsa_private.pem"))
    RSA_PUBLIC_KEY_PATH = os.getenv("RSA_PUBLIC_KEY_PATH", os.path.join("security", "rsa_public.pem"))

    # Operator passphrase that the backup encryption key is derived from.
    # Prevents key-beside-ciphertext exposure: the key is never written to disk,
    # so stealing the backup file no longer hands over the plaintext database.
    # Can also be supplied per-request as a "passphrase" field on the backup and
    # verify endpoints.
    BACKUP_PASSPHRASE = os.getenv("BACKUP_PASSPHRASE", "")

    # ------------------------------------------------------------------
    # Protocol level: secure mail (SMTP over STARTTLS, submission port 587)
    # ------------------------------------------------------------------
    # Credentials come only from the environment. Never commit a real mailbox
    # password to the repository. When these are unset the mailer degrades to a
    # "not configured" result instead of raising, so the prototype still runs.
    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_FROM = os.getenv("SMTP_FROM", "")
    # Keeps a misconfigured or unreachable mail host from hanging a login.
    SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "10"))

    # ------------------------------------------------------------------
    # Protocol level: secure file transfer (SFTP inside SSH, port 22)
    # ------------------------------------------------------------------
    SFTP_HOST = os.getenv("SFTP_HOST", "")
    SFTP_PORT = int(os.getenv("SFTP_PORT", "22"))
    SFTP_USER = os.getenv("SFTP_USER", "")
    # Private key file used for public-key authentication (no passwords on the wire).
    SFTP_KEY_PATH = os.getenv("SFTP_KEY_PATH", "")
    # Pinned server public keys. Host key verification is mandatory, so this file
    # must exist and must already contain the server's key.
    SFTP_KNOWN_HOSTS = os.getenv("SFTP_KNOWN_HOSTS", os.path.join("security", "known_hosts"))
    SFTP_REMOTE_DIR = os.getenv("SFTP_REMOTE_DIR", "securebank-backups")
    SFTP_TIMEOUT = int(os.getenv("SFTP_TIMEOUT", "15"))

    # React SPA dev origin (Vite) allowed to call this API with credentials.
    # HTTPS is the documented default for both processes (see scripts/generate_cert.py).
    CORS_ORIGIN = os.getenv("CORS_ORIGIN", "https://localhost:5173")
    # Frontend (localhost:5173) and API (localhost:5000) are different origins, so the
    # session cookie must be SameSite=None (with Secure, since we're on HTTPS) to be sent
    # on cross-origin fetch() calls. SameSite=Lax silently drops it on XHR/fetch.
    SESSION_COOKIE_SAMESITE = "None"
    SESSION_COOKIE_SECURE = True

    # CSRF tokens live as long as the session rather than expiring on their own
    # clock. The session already times out after SESSION_TIMEOUT_SECONDS, and a
    # second, shorter deadline only produces confusing mid-form failures.
    WTF_CSRF_TIME_LIMIT = None
    # The SPA sends the token in this header; the default list also accepts it
    # as a form field, which this JSON API never uses.
    WTF_CSRF_HEADERS = ["X-CSRFToken", "X-CSRF-Token"]
    # Flask-WTF otherwise demands, on HTTPS, that the Referer header match the
    # API's own origin. The SPA is served from a different origin (port 5173)
    # than the API (port 5000), so that check can never pass here and would
    # reject every legitimate request. The protection that actually matters is
    # the session-bound token: an attacker's page can make the browser send our
    # cookie, but the same-origin policy stops it reading the token to echo
    # back, and CORS_ORIGIN already restricts who may read our responses.
    WTF_CSRF_SSL_STRICT = False
