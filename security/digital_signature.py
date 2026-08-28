"""RSA digital signatures protecting transaction integrity.

New signatures use **RSASSA-PSS** (Probabilistic Signature Scheme, RFC 8017
section 8.1) over a SHA-256 digest. PSS is the current recommendation and the
scheme named in the CW1 design document: it adds a random salt so signing the
same payload twice produces different signatures, and it has a security proof
reducing to the RSA problem, which the older scheme does not.

Verification also accepts **RSASSA-PKCS#1 v1.5** (RFC 8017 section 8.2), the
deterministic scheme this prototype used previously, so transaction rows signed
by earlier demo runs still read back as VERIFIED rather than being reported as
tampered. Nothing new is ever signed with it.
"""

from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15, pss


SCHEME_PSS = "RSASSA-PSS (SHA-256, MGF1)"
SCHEME_PKCS1_V15 = "RSASSA-PKCS#1 v1.5 (SHA-256, legacy)"
SCHEME_NONE = "unverified"


def sign_data(data: bytes, private_key) -> bytes:
    """Sign a payload with RSASSA-PSS over SHA-256."""
    digest = SHA256.new(data)
    return pss.new(private_key).sign(digest)


def verify_signature_detailed(data: bytes, signature: bytes, public_key) -> tuple[bool, str]:
    """Verify a signature and report which scheme accepted it.

    PSS is tried first because it is what everything new is signed with; the
    PKCS#1 v1.5 attempt is only reached for records predating the upgrade.
    """
    digest = SHA256.new(data)

    try:
        pss.new(public_key).verify(digest, signature)
        return True, SCHEME_PSS
    except (ValueError, TypeError):
        pass

    # Legacy compatibility path for transactions signed before the PSS upgrade.
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True, SCHEME_PKCS1_V15
    except (ValueError, TypeError):
        return False, SCHEME_NONE


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    """Boolean form of verify_signature_detailed, for callers that only need pass/fail."""
    valid, _scheme = verify_signature_detailed(data, signature, public_key)
    return valid
