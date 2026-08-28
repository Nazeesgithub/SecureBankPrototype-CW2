"""Proof that stored transactions are integrity-checked when they are read back.

A signature that is written and never verified is decoration. This script writes
a real transaction, then edits the encrypted row directly in SQLite - behind the
application's back, exactly as someone with database access would - and confirms
that GET /api/transactions reports it as TAMPERED rather than SUCCESS.

Two different attacks are demonstrated, because they are caught by two different
controls:

  Scenario A - flip a byte in the ciphertext.
      Caught by AES-256-GCM: the authentication tag no longer matches, so the
      field fails to decrypt at all.

  Scenario B - re-encrypt a *different* amount with the correct AES key.
      This produces a perfectly valid ciphertext, so AES-GCM is satisfied and
      the record decrypts cleanly. Only the RSA signature catches it, because
      the signed payload covers the ciphertext that was originally stored.
      This is the scenario that isolates the digital signature as the control
      doing the work.

Usage:
    1. Start the API in another terminal:   python app.py
    2. Run from the project root:           python scripts/test_tamper.py
"""

import base64
import json
import os
import sqlite3
import ssl
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pyotp

PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Running "python scripts/test_tamper.py" puts scripts/ on sys.path, not the
# project root, so make the project's own packages importable.
sys.path.insert(0, str(PROJECT_ROOT))

# The project's own crypto helpers, so the "attacker" uses the real algorithms.
from security.aes import aes_encrypt  # noqa: E402
from security.rsa import load_private_key, rsa_decrypt  # noqa: E402

DB_PATH = os.getenv("DATABASE_PATH", str(PROJECT_ROOT / "database" / "bank.db"))
API_BASE = os.getenv("API_BASE", "https://127.0.0.1:5000/api")
RSA_PRIVATE_KEY_PATH = os.getenv(
    "RSA_PRIVATE_KEY_PATH", str(PROJECT_ROOT / "security" / "rsa_private.pem")
)
LOG_PATH = os.getenv("LOG_PATH", str(PROJECT_ROOT / "logs" / "security.log"))

SENDER_USERNAME = "tamper_sender"
RECEIVER_USERNAME = "tamper_receiver"
PASSWORD = "TamperTest@123"
TRANSFER_AMOUNT = "500.00"
FORGED_AMOUNT = "9999999.00"

_ssl_context = ssl._create_unverified_context()
_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context))


def _http(method, path, payload=None, cookie=None, csrf=None):
    """Raw request. Returns (status_code, parsed_json_body, set_cookie_header)."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CSRFToken"] = csrf

    request = urllib.request.Request(API_BASE + path, data=data, headers=headers, method=method)
    try:
        with _opener.open(request, timeout=30) as response:
            body = response.read()
            return response.status, (json.loads(body) if body else {}), response.headers.get("Set-Cookie")
    except urllib.error.HTTPError as error:
        body = error.read()
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"message": body[:200].decode("utf-8", "replace")}
        return error.code, parsed, error.headers.get("Set-Cookie")
    except urllib.error.URLError as error:
        sys.exit(f"Cannot reach the API at {API_BASE} ({error.reason}).\nStart it first with: python app.py")


# The API enforces CSRF on every state-changing method, so a token bound to the
# session must accompany each one. Tokens are cached per session cookie.
_csrf_by_cookie = {}
_anonymous = {"cookie": None, "csrf": None}


def _fetch_csrf(cookie):
    status, body, set_cookie = _http("GET", "/csrf-token", None, cookie)
    if status != 200:
        sys.exit(f"Could not obtain a CSRF token: HTTP {status}")
    new_cookie = set_cookie.split(";")[0] if set_cookie else cookie
    return body["csrfToken"], new_cookie


def call(method, path, payload=None, cookie=None):
    """Same signature as before, but transparently attaches a CSRF token."""
    if method == "GET":
        return _http(method, path, payload, cookie)

    if cookie is None:
        # Registration and login happen before there is a logged-in session. The
        # token request itself starts a session, so its cookie has to be reused
        # for the POST that follows or the token will not match.
        if _anonymous["csrf"] is None:
            _anonymous["csrf"], _anonymous["cookie"] = _fetch_csrf(None)
        cookie, csrf = _anonymous["cookie"], _anonymous["csrf"]
    else:
        if cookie not in _csrf_by_cookie:
            _csrf_by_cookie[cookie] = _fetch_csrf(cookie)[0]
        csrf = _csrf_by_cookie[cookie]

    return _http(method, path, payload, cookie, csrf)


def connect_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    return db


def seed_and_login():
    """Create the two accounts, clear old rows, and return an authenticated cookie."""
    for username in (SENDER_USERNAME, RECEIVER_USERNAME):
        status, body, _ = call(
            "POST",
            "/register",
            {
                "name": username.replace("_", " ").title(),
                "username": username,
                "email": f"{username}@securebank.local",
                "password": PASSWORD,
                "confirmPassword": PASSWORD,
            },
        )
        if status not in (200, 409):
            sys.exit(f"Could not seed {username}: HTTP {status} {body.get('message')}")

    db = connect_db()
    try:
        db.execute(
            "UPDATE users SET current_balance_minor = 1000000, wallet_balance_minor = 0, "
            "failed_attempts = 0, locked_until = NULL WHERE username IN (?, ?)",
            (SENDER_USERNAME, RECEIVER_USERNAME),
        )
        # Start from exactly one transaction so the output is unambiguous.
        db.execute(
            "DELETE FROM transactions WHERE sender = ? OR receiver = ?",
            (SENDER_USERNAME, SENDER_USERNAME),
        )
        db.commit()
        otp_secret = db.execute(
            "SELECT otp_secret FROM users WHERE username = ?", (SENDER_USERNAME,)
        ).fetchone()["otp_secret"]
        receiver_account = db.execute(
            "SELECT account_number FROM users WHERE username = ?", (RECEIVER_USERNAME,)
        ).fetchone()["account_number"]
    finally:
        db.close()

    status, body, set_cookie = call(
        "POST", "/login", {"username": SENDER_USERNAME, "password": PASSWORD, "portal": "customer"}
    )
    if status != 200:
        sys.exit(f"Login failed: HTTP {status} {body.get('message')}")
    cookie = set_cookie.split(";")[0]

    status, body, set_cookie = call(
        "POST", "/otp/verify", {"otp": pyotp.TOTP(otp_secret, interval=30).now()}, cookie=cookie
    )
    if status != 200:
        sys.exit(f"OTP verification failed: HTTP {status} {body.get('message')}")
    if set_cookie:
        cookie = set_cookie.split(";")[0]

    return cookie, receiver_account


def make_transaction(cookie, receiver_account):
    status, body, _ = call(
        "POST",
        "/transfer",
        {
            "receiver": receiver_account,
            "amount": TRANSFER_AMOUNT,
            "description": "tamper demo",
            "source": "card",
        },
        cookie=cookie,
    )
    if status != 200:
        sys.exit(f"Transfer failed: HTTP {status} {body.get('message')}")


def read_row():
    """Return the stored transaction row for the test sender."""
    db = connect_db()
    try:
        return db.execute(
            "SELECT id, encrypted_amount, encrypted_message, encrypted_aes_key, signature "
            "FROM transactions WHERE sender = ? ORDER BY id DESC LIMIT 1",
            (SENDER_USERNAME,),
        ).fetchone()
    finally:
        db.close()


def write_encrypted_amount(row_id, value):
    """Edit the ciphertext directly, bypassing the application entirely."""
    db = connect_db()
    try:
        db.execute("UPDATE transactions SET encrypted_amount = ? WHERE id = ?", (value, row_id))
        db.commit()
    finally:
        db.close()


def report(cookie):
    """Ask the API how it judges the stored row."""
    status, body, _ = call("GET", "/transactions", cookie=cookie)
    if status != 200:
        sys.exit(f"/api/transactions failed: HTTP {status} {body.get('message')}")
    rows = body["transactions"]
    if not rows:
        sys.exit("No transactions returned for the test account.")
    tx = rows[0]
    return {
        "signatureValid": tx.get("signatureValid"),
        "signatureStatus": tx.get("signatureStatus"),
        "amount": tx.get("amount"),
        "scheme": tx["security"].get("signatureScheme"),
        "detail": tx["security"].get("signatureDetail"),
    }


def show(label, result, expect_valid):
    ok = result["signatureValid"] is expect_valid
    print(f"  {label}")
    print(f"    signatureStatus : {result['signatureStatus']}")
    print(f"    signatureValid  : {result['signatureValid']}")
    print(f"    amount reported : {result['amount']}")
    print(f"    scheme          : {result['scheme']}")
    print(f"    detail          : {result['detail']}")
    print(f"    [{'PASS' if ok else 'FAIL'}] expected signatureValid={expect_valid}")
    print()
    return ok


def tail_log(marker, count=3):
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, encoding="utf-8") as log_file:
        lines = [l.rstrip("\n") for l in log_file if marker in l]
    return lines[-count:]


def main():
    print("=" * 74)
    print("Transaction integrity test  -  signature verification on read")
    print("=" * 74)
    print(f"API      : {API_BASE}")
    print(f"Database : {DB_PATH}")
    print()

    cookie, receiver_account = seed_and_login()
    make_transaction(cookie, receiver_account)
    row = read_row()
    original_ciphertext = row["encrypted_amount"]
    print(f"Created transaction id={row['id']} for LKR {TRANSFER_AMOUNT}")
    print()

    checks = []

    print("BASELINE - untouched record")
    print("-" * 74)
    checks.append(show("as stored by /api/transfer", report(cookie), expect_valid=True))

    # ---------------------------------------------------------------- Scenario A
    print("SCENARIO A - flip a byte in the encrypted amount (crude edit)")
    print("-" * 74)
    decoded = bytearray(base64.b64decode(original_ciphertext))
    decoded[-1] ^= 0x01  # single bit flip in the ciphertext
    write_encrypted_amount(row["id"], base64.b64encode(bytes(decoded)).decode())
    print("    SQL executed    : UPDATE transactions SET encrypted_amount = <flipped> WHERE id = %d" % row["id"])
    checks.append(show("caught by AES-256-GCM tag check", report(cookie), expect_valid=False))

    write_encrypted_amount(row["id"], original_ciphertext)

    # ---------------------------------------------------------------- Scenario B
    print("SCENARIO B - re-encrypt a different amount with the CORRECT AES key")
    print("-" * 74)
    private_key = load_private_key(RSA_PRIVATE_KEY_PATH)
    aes_key = rsa_decrypt(base64.b64decode(row["encrypted_aes_key"]), private_key)
    forged = aes_encrypt(FORGED_AMOUNT, aes_key)
    write_encrypted_amount(row["id"], forged)
    print(f"    attacker rewrote LKR {TRANSFER_AMOUNT} as LKR {FORGED_AMOUNT}")
    print("    the new ciphertext is validly encrypted, so AES-GCM is satisfied")
    checks.append(show("caught by the RSA signature alone", report(cookie), expect_valid=False))

    # ------------------------------------------------------------------ restore
    write_encrypted_amount(row["id"], original_ciphertext)
    print("RESTORED - original ciphertext put back")
    print("-" * 74)
    checks.append(show("verifies again", report(cookie), expect_valid=True))

    print("Security log evidence")
    print("-" * 74)
    for line in tail_log("SIGNATURE_INVALID"):
        print("  " + line[:160])
    print()

    if all(checks):
        print("RESULT: PASS - tampering is detected on read and logged as SIGNATURE_INVALID.")
        return 0
    print("RESULT: FAIL - at least one case was not judged correctly.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
