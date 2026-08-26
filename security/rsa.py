from pathlib import Path
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


KEY_SIZE_BITS = 2048


def ensure_rsa_keys(private_key_path: str, public_key_path: str) -> None:
    private_path = Path(private_key_path)
    public_path = Path(public_key_path)

    if private_path.exists() and public_path.exists():
        return

    key_pair = RSA.generate(KEY_SIZE_BITS)
    private_path.write_bytes(key_pair.export_key())
    public_path.write_bytes(key_pair.publickey().export_key())


def load_private_key(private_key_path: str):
    return RSA.import_key(Path(private_key_path).read_bytes())


def load_public_key(public_key_path: str):
    return RSA.import_key(Path(public_key_path).read_bytes())


def rsa_encrypt(data: bytes, public_key) -> bytes:
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(data: bytes, private_key) -> bytes:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)
