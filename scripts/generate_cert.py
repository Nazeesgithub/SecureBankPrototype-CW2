"""Create the self-signed TLS certificate used by both processes.

HTTPS is the documented default for this prototype: the Flask API serves TLS
and the Vite dev server serves TLS, so the whole stack runs encrypted end to
end. Both read the same cert.pem / key.pem pair from the project root.

The certificate carries a subjectAltName covering ``localhost``, ``127.0.0.1``
and ``::1``. That matters: browsers have ignored the legacy commonName field
since 2017, so a certificate without a matching SAN entry is rejected outright
no matter what CN it carries.

Usage (from the project root):

    python scripts/generate_cert.py            # writes ./cert.pem and ./key.pem
    python scripts/generate_cert.py --force    # overwrite an existing pair
    python scripts/generate_cert.py --days 30  # shorter validity

The result is self-signed, so a browser will still show a one-time "not
trusted" interstitial. Accept it once per origin (the API on port 5000 and the
dev server on port 5173 are two separate origins, so accept both).
"""

import argparse
import datetime
import ipaddress
import os
import sys
from pathlib import Path

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit(
        "The 'cryptography' package is required to generate a certificate.\n"
        "Install the project dependencies first:  pip install -r requirements.txt"
    )


PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Every name the certificate must be valid for. A browser matches the URL host
# against this list, not against the commonName.
SAN_DNS_NAMES = ["localhost"]
SAN_IP_ADDRESSES = ["127.0.0.1", "::1"]

KEY_SIZE_BITS = 2048


def build_certificate(days: int):
    """Return a (private_key, certificate) pair for the local demo hosts."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE_BITS)

    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "LK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureBankPrototype"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Coursework Demo"),
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        ]
    )

    alt_names = [x509.DNSName(name) for name in SAN_DNS_NAMES]
    alt_names += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in SAN_IP_ADDRESSES]

    now = datetime.datetime.now(datetime.timezone.utc)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        # A minute of backdating absorbs small clock differences between the
        # machine that minted the certificate and the browser reading it.
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=days))
        # The name check that browsers actually perform.
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        # Self-signed leaf, not a CA: it must not be able to vouch for anything else.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Restricts the certificate to TLS server authentication only.
        .add_extension(
            x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
        .sign(private_key, hashes.SHA256())
    )

    return private_key, certificate


def write_pair(private_key, certificate, cert_path: Path, key_path: Path):
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))

    key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            # Unencrypted, because Flask and Vite both need to read the key
            # without a passphrase prompt at startup.
            encryption_algorithm=serialization.NoEncryption(),
        )
    )

    # Best effort on Windows, meaningful on POSIX: the private key is not for
    # other accounts to read.
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--days", type=int, default=365, help="validity in days (default 365)")
    parser.add_argument("--force", action="store_true", help="overwrite an existing pair")
    parser.add_argument(
        "--out-dir",
        default=str(PROJECT_ROOT),
        help="directory to write cert.pem and key.pem into (default: project root)",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir).resolve()
    cert_path = out_dir / "cert.pem"
    key_path = out_dir / "key.pem"

    if (cert_path.exists() or key_path.exists()) and not args.force:
        print(f"cert.pem / key.pem already exist in {out_dir}.")
        print("Nothing written. Re-run with --force to replace them.")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    private_key, certificate = build_certificate(args.days)
    write_pair(private_key, certificate, cert_path, key_path)

    print("Self-signed TLS certificate created.")
    print(f"  Certificate : {cert_path}")
    print(f"  Private key : {key_path}")
    print(f"  Key         : RSA {KEY_SIZE_BITS}-bit, signed with SHA-256")
    print(f"  Valid for   : {args.days} days")
    print(f"  Valid names : {', '.join(SAN_DNS_NAMES + SAN_IP_ADDRESSES)}")
    print()
    print("Both processes pick this up automatically:")
    print("  python app.py          -> https://127.0.0.1:5000")
    print("  cd frontend && npm run dev  -> https://localhost:5173")
    print()
    print("The certificate is self-signed, so accept the browser warning once per")
    print("origin (port 5000 and port 5173 are separate origins).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
