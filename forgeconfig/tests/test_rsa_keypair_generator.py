"""Tests for RSA Key Generator."""

from pathlib import Path

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from log.logger import get_logger as _logger
from security.rsa.keypair_generator import (
    create_secure_key_directory,
    gen_key,
    save_key_pair,
)

logger = _logger("rsa_keypair_tests")


class KeyVerificationError(Exception):  # noqa: D101
    def __init__(self, *args):  # noqa: D107
        super().__init__(*args)


def verify_keypair(
    private_key: rsa.RSAPrivateKey, public_key: rsa.RSAPublicKey
) -> bool:
    """Verify if an RSA keypair is valid by performing multiple checks.

      Checks:
      1. Encryption/Decryption test
      2. Signature/Verification test
      3. Key size match
      4. Public exponent match

    Args:
        private_key: RSA private key object
        public_key: RSA public key object

    Returns:
        bool: True if keypair is valid, False otherwise

    """
    try:
        # Test message
        message = b"Test message for RSA keypair verification"

        # Encryption/Decryption
        cipher_text = public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        decrypted = private_key.decrypt(
            cipher_text,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        if decrypted != message:
            return False

        # Signature/Verification
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )

        try:
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )
        except Exception:
            return False

        # Key size match
        if private_key.key_size != public_key.key_size:
            return False

        # Public exponent match
        private_numbers = private_key.private_numbers()
        public_numbers = public_key.public_numbers()

        if private_numbers.public_numbers.e != public_numbers.e:
            return False

        return True

    except Exception as e:
        raise KeyVerificationError(f"Verification failed: {str(e)}")


def load_private_key(
    private_key_path: str | Path, passphrase: str | bytes | None = None
) -> rsa.RSAPrivateKey:
    """Load a private key from file, handling both encrypted and unencrypted keys.

    Args:
        private_key_path: Path to the private key file
        passphrase: Optional passphrase for encrypted keys

    Returns:
        rsa.RSAPrivateKey: Loaded private key object

    Raises:
        ValueError: If passphrase is required but not provided
        OSError: If file reading fails

    """
    if passphrase is not None and isinstance(passphrase, str):
        passphrase = passphrase.encode()

    with open(private_key_path, "rb") as key_file:
        try:
            private_key = serialization.load_pem_private_key(
                key_file.read(), password=passphrase, backend=default_backend()
            )
            return private_key
        except ValueError as e:
            if "Password was not given but private key is encrypted" in str(e):
                raise ValueError(
                    "Private key is encrypted. Please provide passphrase."
                ) from e
            raise


def load_public_key(public_key_path: str | Path) -> rsa.RSAPublicKey:
    """Load a public key from file.

    Args:
        public_key_path: Path to the public key file

    Returns:
        rsa.RSAPublicKey: Loaded public key object

    Raises:
        OSError: If file reading fails

    """
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(), backend=default_backend()
        )
        return public_key


def verify_keypair_files(
    private_key_path: str | Path,
    public_key_path: str | Path,
    passphrase: str | bytes | None = None,
) -> bool:
    """Verify if a keypair stored in files is valid, handling both encrypted and unencrypted keys.

    Args:
        private_key_path: Path to private key file
        public_key_path: Path to public key file
        passphrase: Optional passphrase for encrypted private key

    Returns:
        bool: True if keypair is valid, False otherwise

    """
    try:
        # Load keys
        private_key = load_private_key(private_key_path, passphrase)
        public_key = load_public_key(public_key_path)

        # Verify using the existing verify_keypair function
        return verify_keypair(private_key, public_key)

    except Exception as e:
        print(f"Keypair verification failed: {str(e)}")
        return False


@pytest.fixture
def keys_dir():  # noqa: D103
    _keys_dir = Path(__file__).parent.resolve().joinpath("keys")
    _keys_dir = create_secure_key_directory(_keys_dir)
    yield _keys_dir
    # will be just one level
    for f in _keys_dir.iterdir():
        if f.is_file():
            Path.unlink(f)
    Path.rmdir(_keys_dir)


def test_create_keys_directory(keys_dir):  # noqa: D103
    assert keys_dir is not None
    assert keys_dir.exists() is True
    assert keys_dir.is_dir() is True
    mode = oct(keys_dir.stat().st_mode)[-3:]
    assert mode == "700"


def test_save_key_pair(keys_dir):  # noqa: D103
    private_key_path = keys_dir.joinpath("test_pk.p8")
    public_key_path = keys_dir.joinpath("test_pk.pub")
    private_key_passphrase = "test123@@"

    private_key = gen_key()[0]
    is_created = save_key_pair(
        private_key,
        private_key_path,
        public_key_path,
        private_key_passphrase,
    )

    assert is_created is True
    assert Path.exists(private_key_path) is True
    assert Path.exists(public_key_path) is True

    ## check file permissions
    mode = oct(private_key_path.stat().st_mode)[-3:]
    assert mode == "600"

    mode = oct(public_key_path.stat().st_mode)[-3:]
    assert mode == "644"

    is_valid = verify_keypair_files(
        private_key_path,
        public_key_path,
        passphrase=private_key_passphrase,
    )
    assert is_valid is True


def test_save_key_pair_without_passphrase(keys_dir):  # noqa: D103
    with pytest.raises(ValueError) as no_passphrase_err:
        private_key_path = keys_dir.joinpath("test_pk.p8")
        public_key_path = keys_dir.joinpath("test_pk.pub")

        private_key = gen_key()[0]
        _ = save_key_pair(
            private_key,
            private_key_path,
            public_key_path,
            None,
        )

    assert isinstance(no_passphrase_err, ValueError) is not None
    assert (
        str(no_passphrase_err.value)
        == "Passphrase is required to encrypt the private key."
    )
