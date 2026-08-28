import pyotp


# Label shown next to the account inside Google / Microsoft Authenticator.
OTP_ISSUER = "SecureBankPrototype"


def generate_otp_secret() -> str:
    return pyotp.random_base32()


def get_totp(secret: str) -> pyotp.TOTP:
    return pyotp.TOTP(secret, interval=30)


def provisioning_uri(secret: str, username: str, issuer: str = OTP_ISSUER) -> str:
    """Build the otpauth:// URI that an authenticator app enrols from.

    Scanning (or pasting) this URI loads the shared secret into Google
    Authenticator / Microsoft Authenticator, so the 6-digit code is generated
    on the user's own device instead of being handed out by the server.
    """
    return get_totp(secret).provisioning_uri(name=username, issuer_name=issuer)


def current_otp(secret: str) -> str:
    return get_totp(secret).now()


def verify_otp(secret: str, otp_code: str) -> bool:
    # valid_window=1 allows small clock drift for demo purposes.
    return get_totp(secret).verify(otp_code, valid_window=1)
