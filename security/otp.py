import pyotp


def generate_otp_secret() -> str:
    return pyotp.random_base32()


def get_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret, interval=30)


def current_otp(secret: str) -> str:
    return get_totp(secret).now()


def verify_otp(secret: str, otp_code: str) -> bool:
    # valid_window=1 allows small clock drift for demo purposes.
    return get_totp(secret).verify(otp_code, valid_window=1)
