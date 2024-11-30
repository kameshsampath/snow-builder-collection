# Standard library
import os
import logging
import stat
from getpass import getpass
from pathlib import Path
from typing import Optional, Union

# Third party
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from log.logger import get_logger as _logger

logger = _logger("rsa_keypair_generator")


class KeyPairSaveError(Exception):
    def __init__(self, *args):
        super().__init__(*args)


def create_secure_key_directory(directory: Path | str = None) -> Path:
    """
    Create a directory for storing private keys with secure permissions (700).

    Args:
        directory: Path where to create the secure directory. If None it creates the default directory on user home `.ssh`(~/.ssh)

    Returns:
        Path: Path object pointing to the created directory

    Raises:
        PermissionError: If unable to set required permissions
        OSError: If directory creation fails
    """
    if directory is None:
        # create the default ~/.ssh directory
        directory = Path.joinpath(Path.home, ".ssh")

    key_dir = Path(directory)

    # Create directory and parents if they don't exist
    key_dir.mkdir(parents=True, exist_ok=True)

    # Set secure permissions (700 - owner rwx only)
    key_dir.chmod(mode=stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)

    return key_dir


def get_secure_password(
    prompt: str = "Enter encryption password: ",
    confirm: bool = True,
    min_length: int = 8,
) -> Optional[str]:
    """
    Securely get a password from the user with confirmation and validation.

    This function prompts for a password without echoing the input to the screen,
    optionally confirms it by asking twice, and validates the minimum length.

    Args:
        prompt: Custom prompt message to display
        confirm: Whether to ask for password confirmation
        min_length: Minimum required password length

    Returns:
        str: The validated password if successful
        None: If passwords don't match or user interrupts (Ctrl+C)

    Raises:
        ValueError: If the password is too short
    """
    try:
        password = getpass(prompt)

        if len(password) < min_length:
            raise ValueError(f"Password must be at least {min_length} characters long")

        if confirm:
            confirm_password = getpass("Confirm password: ")
            if password != confirm_password:
                print("Passwords do not match!")
                return None

        return password

    except KeyboardInterrupt:
        print("\nPassword input cancelled by user")
        return None


def gen_key(key_size: int = 4096) -> rsa.RSAPrivateKey:
    """
    Generate a new RSA private key with specific parameters.

    This function creates an RSA private key using the default cryptographic backend.
    The key is generated with a specified key size and public exponent value for
    optimal security and performance.

    Key parameters:
        - key_size(int,4096): The encryption key size
        - Public exponent: 65537 - a standard Fermat prime for RSA

    Returns:
        rsa.RSAPrivateKey: A newly generated RSA private key object

    Raises:
        ValueError: If KEY_SIZE is not a valid key length
        TypeError: If backend does not support the required operations

    Example:
        private_key = gen_key()
        # The public key can be derived using:
        public_key = private_key.public_key()
    """
    PUBLIC_EXPONENT = 65537
    key = rsa.generate_private_key(
        backend=default_backend(),
        key_size=key_size,
        public_exponent=PUBLIC_EXPONENT,
    )
    logger.info("Successfully generated the RSA Key")
    return key


def save_private_key(
    private_key: rsa.RSAPrivateKey,
    filename: Union[str, Path],
    passphrase: Union[str, bytes] = None,
) -> None:
    """
    Save an encrypted private key to file with secure permissions.

    Args:
        private_key: RSA private key object
        filename: Path to save the private key
        passphrase(str,optional): String or bytes used to encrypt the private key

    Raises:
        ValueError: If the passphrase is empty
        OSError: If there are file permission or writing errors
        TypeError: If the arguments are of incorrect type
    """
    logger.debug(f"Saving generated RSA Key to {filename}")
    pem = None
    # Convert passphrase to bytes
    if passphrase is not None:
        if isinstance(passphrase, str):
            passphrase = passphrase.encode()
            # Serialize the private key with encryption
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
            )
    else:
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    if pem is not None:
        # Write to file with secure permissions
        with open(filename, "wb") as f:
            # Set file permissions to read/write for owner only (0600)
            os.chmod(filename, stat.S_IRUSR | stat.S_IWUSR)
            f.write(pem)


def save_public_key(
    public_key: rsa.RSAPublicKey, filename: Union[str, Path] = None
) -> str:
    """
    Save a public key to file.

    Args:
        public_key: RSA public key object
        filename(Path,str,optional): Path to save the public key.

    Raises:
        OSError: If there are file permission or writing errors
        TypeError: If the arguments are of incorrect type
    """
    logger.debug(f"Saving generated RSA Public Key to {filename}")
    # Get public key
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    if filename is not None:
        # Write to file
        with open(filename, "wb") as f:
            # Set file permissions to read for all, write for owner (0644)
            os.chmod(
                filename, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH
            )
            f.write(pem)

    pub_key_str = pem.decode("utf-8")
    pub_key_str = pub_key_str.replace("-----BEGIN PUBLIC KEY-----", "")
    pub_key_str = pub_key_str.replace("-----END PUBLIC KEY-----", "")
    pub_key_str = pub_key_str.replace("\n", "")

    return pub_key_str.strip()


def save_key_pair(
    private_key: rsa.RSAPrivateKey,
    private_key_path: Union[str, Path],
    public_key_path: Union[str, Path],
    passphrase: Union[str, bytes] = None,
) -> bool:
    """
    Save both private and public keys securely.

    Args:
        private_key: RSA private key object
        passphrase: String or bytes used to encrypt the private key
        private_key_path: Path to save the private key
        public_key_path: Path to save the public key

    Returns:
        bool: True if both keys were saved successfully, False otherwise

    Raises:
        ValueError: If the passphrase is empty
        OSError: If there are file permission or writing errors
        TypeError: If the arguments are of incorrect type
    """
    logger.debug(
        f"Saving generated RSA KeyPair to {private_key_path}/{public_key_path}"
    )
    try:
        # Save private key
        save_private_key(private_key, private_key_path, passphrase)

        # Save public key
        public_key = private_key.public_key()
        save_public_key(public_key, public_key_path)

        return True
    except Exception as e:
        logger.error(f"Error saving keypair {e}")
        raise KeyPairSaveError(e)
