"""Proof that /api/transfer is safe against the TOCTOU double-spend race.

Six transfers of 900 are fired simultaneously from an account holding exactly
1000. Only one of them can legitimately succeed. Before the fix, all six passed
the balance check against the same stale read and the sender was debited once;
after the fix, the conditional UPDATE inside BEGIN IMMEDIATE lets exactly one
through and rejects the rest with HTTP 400.

Usage:
    1. Start the API in another terminal:   python app.py
    2. Run this script from the project root:   python scripts/test_race.py

Only the standard library plus pyotp (already a project dependency) is used.
The OTP is computed locally from the seeded account's secret, because the API
deliberately no longer returns the code in the login response.
"""

import json
import os
import sqlite3
import ssl
import sys
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pyotp

from decimal import Decimal

# --------------------------------------------------------------------------
# Test parameters
# --------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = os.getenv("DATABASE_PATH", str(PROJECT_ROOT / "database" / "bank.db"))
# HTTPS is the documented default for the API (see scripts/generate_cert.py).
API_BASE = os.getenv("API_BASE", "https://127.0.0.1:5000/api")

SENDER_USERNAME = "race_sender"
RECEIVER_USERNAME = "race_receiver"
PASSWORD = "RaceTest@123"

# Money is exact Decimal here too, and is written to the database in the same
# integer minor units (cents) the application stores.
STARTING_BALANCE = Decimal("1000.00")
TRANSFER_AMOUNT = Decimal("900.00")
CONCURRENT_TRANSFERS = 6

# Only one 900 debit fits inside a 1000 balance.
EXPECTED_SUCCESSES = 1
EXPECTED_SENDER_BALANCE = STARTING_BALANCE - TRANSFER_AMOUNT
EXPECTED_RECEIVER_BALANCE = TRANSFER_AMOUNT


def to_minor(amount: Decimal) -> int:
    return int(amount * 100)


def from_minor(minor: int) -> Decimal:
    return (Decimal(int(minor)) / 100).quantize(Decimal("0.01"))

# Self-signed certificates are expected when the API is run over HTTPS.
_ssl_context = ssl._create_unverified_context()
_opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=_ssl_context))


# --------------------------------------------------------------------------
# Tiny HTTP helper (stdlib only)
# --------------------------------------------------------------------------
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


# --------------------------------------------------------------------------
# Seeding
# --------------------------------------------------------------------------
def seed_accounts():
    """Create the two test accounts (once) and reset their balances each run."""
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
        # 409 simply means the account survives from a previous run.
        if status not in (200, 409):
            sys.exit(f"Could not seed {username}: HTTP {status} {body.get('message')}")

    if not os.path.exists(DB_PATH):
        sys.exit(f"Database not found at {DB_PATH}.")

    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        db.execute(
            "UPDATE users SET current_balance_minor = ?, wallet_balance_minor = 0, "
            "failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (to_minor(STARTING_BALANCE), SENDER_USERNAME),
        )
        db.execute(
            "UPDATE users SET current_balance_minor = 0, wallet_balance_minor = 0, "
            "failed_attempts = 0, locked_until = NULL WHERE username = ?",
            (RECEIVER_USERNAME,),
        )
        # Clear ledger rows from earlier runs so the row count is meaningful.
        db.execute("DELETE FROM transactions WHERE sender = ?", (SENDER_USERNAME,))
        db.commit()

        rows = {
            row["username"]: row
            for row in db.execute(
                "SELECT username, otp_secret, account_number FROM users WHERE username IN (?, ?)",
                (SENDER_USERNAME, RECEIVER_USERNAME),
            )
        }
    finally:
        db.close()

    return rows[SENDER_USERNAME]["otp_secret"], rows[RECEIVER_USERNAME]["account_number"]


def read_balances():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        sender = from_minor(db.execute(
            "SELECT current_balance_minor FROM users WHERE username = ?", (SENDER_USERNAME,)
        ).fetchone()["current_balance_minor"])
        receiver = from_minor(db.execute(
            "SELECT current_balance_minor FROM users WHERE username = ?", (RECEIVER_USERNAME,)
        ).fetchone()["current_balance_minor"])
        ledger_rows = db.execute(
            "SELECT COUNT(*) AS n FROM transactions WHERE sender = ?", (SENDER_USERNAME,)
        ).fetchone()["n"]
    finally:
        db.close()
    return sender, receiver, ledger_rows


# --------------------------------------------------------------------------
# Login (password + locally generated TOTP)
# --------------------------------------------------------------------------
def login(otp_secret):
    status, body, set_cookie = call(
        "POST", "/login", {"username": SENDER_USERNAME, "password": PASSWORD, "portal": "customer"}
    )
    if status != 200:
        sys.exit(f"Login failed: HTTP {status} {body.get('message')}")

    cookie = set_cookie.split(";")[0] if set_cookie else None
    if not cookie:
        sys.exit("Login did not return a session cookie.")

    otp_code = pyotp.TOTP(otp_secret, interval=30).now()
    status, body, set_cookie = call("POST", "/otp/verify", {"otp": otp_code}, cookie=cookie)
    if status != 200:
        sys.exit(f"OTP verification failed: HTTP {status} {body.get('message')}")

    # Flask-Login rotates the cookie once the session is authenticated.
    if set_cookie:
        cookie = set_cookie.split(";")[0]
    return cookie


# --------------------------------------------------------------------------
# The race itself
# --------------------------------------------------------------------------
def fire_transfers(cookie, receiver_account_number):
    """Release all requests from a barrier so they hit the endpoint together."""
    barrier = threading.Barrier(CONCURRENT_TRANSFERS)

    def attempt(index):
        payload = {
            "receiver": receiver_account_number,
            "amount": f"{TRANSFER_AMOUNT:.2f}",
            "description": f"race test #{index}",
            "source": "card",
        }
        barrier.wait()
        status, body, _ = call("POST", "/transfer", payload, cookie=cookie)
        return index, status, body.get("message", "")

    with ThreadPoolExecutor(max_workers=CONCURRENT_TRANSFERS) as pool:
        return sorted(pool.map(attempt, range(1, CONCURRENT_TRANSFERS + 1)))


def main():
    print("=" * 70)
    print("Double-spend race test  -  /api/transfer")
    print("=" * 70)
    print(f"API           : {API_BASE}")
    print(f"Database      : {DB_PATH}")
    print(f"Scenario      : {CONCURRENT_TRANSFERS} concurrent transfers of "
          f"{TRANSFER_AMOUNT:.2f} from a balance of {STARTING_BALANCE:.2f}")
    print()

    otp_secret, receiver_account_number = seed_accounts()
    cookie = login(otp_secret)
    print(f"Logged in as {SENDER_USERNAME}; receiver account {receiver_account_number}")
    print()

    results = fire_transfers(cookie, receiver_account_number)

    print("Responses")
    print("-" * 70)
    for index, status, message in results:
        verdict = "ACCEPTED" if status == 200 else "rejected"
        print(f"  transfer #{index}: HTTP {status} {verdict:9s} {message}")
    print()

    successes = sum(1 for _, status, _ in results if status == 200)
    server_errors = [r for r in results if r[1] >= 500]
    sender_balance, receiver_balance, ledger_rows = read_balances()

    print("Final state")
    print("-" * 70)
    print(f"  Accepted transfers : {successes}  (expected {EXPECTED_SUCCESSES})")
    print(f"  Sender balance     : {sender_balance:.2f}  (expected {EXPECTED_SENDER_BALANCE:.2f})")
    print(f"  Receiver balance   : {receiver_balance:.2f}  (expected {EXPECTED_RECEIVER_BALANCE:.2f})")
    print(f"  Ledger rows        : {ledger_rows}  (expected {EXPECTED_SUCCESSES})")
    print()

    checks = [
        ("exactly one transfer accepted", successes == EXPECTED_SUCCESSES),
        # Exact equality is now meaningful: these are Decimals, not floats.
        ("sender debited exactly once", sender_balance == EXPECTED_SENDER_BALANCE),
        ("receiver credited exactly once", receiver_balance == EXPECTED_RECEIVER_BALANCE),
        ("ledger row count matches accepted transfers", ledger_rows == successes),
        ("balance never went negative", sender_balance >= 0),
        ("no server errors", not server_errors),
    ]

    for label, ok in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {label}")
    print()

    if all(ok for _, ok in checks):
        print("RESULT: PASS - the balance is correct; the double-spend race is closed.")
        return 0

    print("RESULT: FAIL - the final balance is wrong; the race is still exploitable.")
    if server_errors:
        print("        (server errors above usually mean SQLite lock contention, not a double spend)")
    return 1


if __name__ == "__main__":
    sys.exit(main())
