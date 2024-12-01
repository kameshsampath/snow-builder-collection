"""Utility for handling common key operations."""

import base64
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from log.logger import get_logger as _logger

logger = _logger("key_util")


def load_rsa_public_key(key: Path | str) -> rsa.RSAPublicKey:
    """Load an RSA public key from a file in PEM format.

    Args:
        key: Path of public key or string to the public key file content

    Returns:
        RSAPublicKey: Loaded public key object

    Raises:
        ValueError: If file doesn't contain a valid RSA public key
        FileNotFoundError: If key file doesn't exist

    """
    key_data = None
    if isinstance(key, Path):
        logger.debug(f"using file {key} to load public key")
        with open(key, "rb") as f:
            key_data = f.read()
    else:
        logger.debug("public key string")
        key_data = bytes(key)

    logger.debug(f"Public Key Data:{key_data}")

    try:
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend(),
        )
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Not an RSA public key")
        return public_key
    except Exception as e:
        raise ValueError(f"Failed to load public key: {e}")


def get_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Calculate SHA256 fingerprint of an RSA public key.

    Args:
        public_key: RSA public key

    Returns:
        str: a base64 encoded SHA256 fingerprint.

    """
    # Get DER encoding of the public key
    key_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Calculate Hash
    digest = hashes.Hash(hashes.SHA256())
    digest.update(key_der)
    fingerprint_bytes = digest.finalize()

    # Base64 Encoded FingerPrint
    base64_fingerprint = base64.b64encode(fingerprint_bytes).decode("ascii")

    return base64_fingerprint


def match_fingerprints(left_fp: str, right_fp: str) -> bool:
    """Compare two RSA public keys by their fingerprints.

    Args:
        left_fp: First public key fingerprint
        right_fp: Second public key fingerprint

    Returns:
        bool: Whether the keys have matched or not

    """
    return left_fp == right_fp
