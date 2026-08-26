import base64
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad


AES_KEY_SIZE = 32  # 256-bit key


def generate_aes_key() -> bytes:
    return get_random_bytes(AES_KEY_SIZE)


def aes_encrypt(plain_text: str, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    cipher_text, tag = cipher.encrypt_and_digest(plain_text.encode("utf-8"))
    payload = b"GCM1" + cipher.nonce + tag + cipher_text
    return base64.b64encode(payload).decode("utf-8")


def aes_decrypt(encoded_payload: str, key: bytes) -> str:
    return aes_decrypt_bytes(encoded_payload, key).decode("utf-8")


def aes_encrypt_bytes(plain_bytes: bytes, key: bytes) -> str:
    cipher = AES.new(key, AES.MODE_GCM)
    cipher_text, tag = cipher.encrypt_and_digest(plain_bytes)
    payload = b"GCM1" + cipher.nonce + tag + cipher_text
    return base64.b64encode(payload).decode("utf-8")


def aes_decrypt_bytes(encoded_payload: str, key: bytes) -> bytes:
    data = base64.b64decode(encoded_payload.encode("utf-8"))
    if data.startswith(b"GCM1"):
        nonce = data[4:20]
        tag = data[20:36]
        cipher_text = data[36:]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return cipher.decrypt_and_verify(cipher_text, tag)

    # Keep existing prototype records readable after upgrading to GCM.
    iv = data[: AES.block_size]
    cipher_text = data[AES.block_size :]
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(cipher_text), AES.block_size)
