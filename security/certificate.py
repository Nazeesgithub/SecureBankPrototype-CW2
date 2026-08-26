import os


def certificate_status(cert_path: str, key_path: str) -> str:
    cert_exists = os.path.exists(cert_path)
    key_exists = os.path.exists(key_path)

    if cert_exists and key_exists:
        return "Self-signed TLS certificate detected"
    return "TLS certificate missing (create cert.pem and key.pem for HTTPS demo)"


def ssl_context_if_available(cert_path: str, key_path: str):
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path
    return None
