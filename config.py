import os


class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-change-me")
    DATABASE_PATH = os.getenv("DATABASE_PATH", os.path.join("database", "bank.db"))
    LOG_PATH = os.getenv("LOG_PATH", os.path.join("logs", "security.log"))

    # Authentication and account security controls
    MAX_LOGIN_ATTEMPTS = 5
    LOCK_MINUTES = 10
    SESSION_TIMEOUT_SECONDS = 20 * 60

    # SSL certificate paths for local HTTPS demo
    SSL_CERT_PATH = os.getenv("SSL_CERT_PATH", "cert.pem")
    SSL_KEY_PATH = os.getenv("SSL_KEY_PATH", "key.pem")

    # Cryptographic key locations
    RSA_PRIVATE_KEY_PATH = os.getenv("RSA_PRIVATE_KEY_PATH", os.path.join("security", "rsa_private.pem"))
    RSA_PUBLIC_KEY_PATH = os.getenv("RSA_PUBLIC_KEY_PATH", os.path.join("security", "rsa_public.pem"))

    # React SPA dev origin (Vite) allowed to call this API with credentials
    CORS_ORIGIN = os.getenv("CORS_ORIGIN", "http://localhost:5173")
    # Frontend (localhost:5173) and API (localhost:5000) are different origins, so the
    # session cookie must be SameSite=None (with Secure, since we're on HTTPS) to be sent
    # on cross-origin fetch() calls. SameSite=Lax silently drops it on XHR/fetch.
    SESSION_COOKIE_SAMESITE = "None"
    SESSION_COOKIE_SECURE = True
