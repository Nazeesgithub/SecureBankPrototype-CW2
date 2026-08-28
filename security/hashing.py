import hashlib
import re

from werkzeug.security import check_password_hash, generate_password_hash


def sha256_hash(plain_text: str) -> str:
    return hashlib.sha256(plain_text.encode("utf-8")).hexdigest()


def sha256_hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# Marks a row whose original unsalted SHA-256 digest has been re-hashed under
# scrypt by the startup migration. See migrate_legacy_password_hashes().
LEGACY_SHA256_PREFIX = "legacy-sha256:"

# The only hash formats this application will accept at rest.
MODERN_HASH_PREFIXES = ("scrypt:", "pbkdf2:")


def password_hash(plain_text: str) -> str:
    return generate_password_hash(plain_text, method="scrypt")


def wrap_legacy_sha256(sha256_digest: str) -> str:
    """Re-hash a stored unsalted SHA-256 digest under scrypt.

    A plain SHA-256 digest cannot be turned back into a scrypt hash of the
    password, because the password itself is not recoverable. What we can do
    is stop storing the bare digest: scrypt-hashing the digest removes the
    unsalted, GPU-crackable value from the database immediately, while still
    letting the account owner log in once more. That successful login supplies
    the plaintext, and the row is then upgraded to an ordinary scrypt hash.
    """
    return LEGACY_SHA256_PREFIX + generate_password_hash(sha256_digest, method="scrypt")


def needs_rehash(expected_hash: str) -> bool:
    """True when this row should be replaced by a direct scrypt hash on login."""
    return not expected_hash.startswith("scrypt:")


def verify_password(plain_text: str, expected_hash: str) -> bool:
    """Check a password against a stored hash.

    Prevents offline password cracking: there is no fallback to unsalted
    SHA-256. A digest with no recognised prefix is treated as unusable and
    rejected outright, rather than being compared with a fast, saltless hash
    that a commodity GPU can reverse at billions of guesses per second.
    """
    if not expected_hash:
        return False

    # Migrated legacy row: the scrypt hash covers the SHA-256 digest of the
    # password, so hash the candidate the same way before comparing.
    if expected_hash.startswith(LEGACY_SHA256_PREFIX):
        wrapped = expected_hash[len(LEGACY_SHA256_PREFIX):]
        return check_password_hash(wrapped, sha256_hash(plain_text))

    if not expected_hash.startswith(MODERN_HASH_PREFIXES):
        return False

    return check_password_hash(expected_hash, plain_text)


def validate_password_complexity(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must contain at least 8 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must include at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must include at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must include at least one digit."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must include at least one special character."
    return True, "Password is valid."
