from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15


def sign_data(data: bytes, private_key) -> bytes:
    digest = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(digest)


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    digest = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except (ValueError, TypeError):
        return False
