import hashlib
import re

from werkzeug.security import check_password_hash, generate_password_hash


def sha256_hash(plain_text: str) -> str:
    return hashlib.sha256(plain_text.encode("utf-8")).hexdigest()


def sha256_hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_sha256(plain_text: str, expected_hash: str) -> bool:
    return sha256_hash(plain_text) == expected_hash


def password_hash(plain_text: str) -> str:
    return generate_password_hash(plain_text, method="scrypt")


def verify_password(plain_text: str, expected_hash: str) -> bool:
    if not expected_hash.startswith(("scrypt:", "pbkdf2:")):
        return verify_sha256(plain_text, expected_hash)
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
