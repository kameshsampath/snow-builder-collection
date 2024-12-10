"""An helper and utility to update Snowflake User object with keys."""

import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from snowflake.core import Root
from snowflake.core.user import User
from snowflake.snowpark.session import Session

from log.logger import get_logger as _logger
from security.rsa.keypair_generator import (
    create_secure_key_directory,
    gen_key,
    save_key_pair,
    save_public_key,
)


class UserKeyError(Exception):
    """Any error that might occur when setting keys for Snowflake User."""

    def __init__(self, *args):  # noqa :D107
        super().__init__(*args)


class UserUtil:
    """UserUtil handles the necessary Snowflake User updates with respect to setting RSA Public Keys.

    This includes:
    - Setting public key for the first time
    - Rotating the public keys
    """

    LOGGER = _logger("user_util")
    KEY_PREFIX = "snowflake_user"
    PRIVATE_KEY_FILE_NAME = f"{KEY_PREFIX}.p8"
    PUBLIC_KEY_FILE_NAME = f"{KEY_PREFIX}.pub"
    SNOWFLAKE_DIR = Path.joinpath(
        Path.home(),
        ".snowflake",
    )

    def __init__(  # noqa :D107
        self,
        session: Session,
        keys_dir: Path | str = SNOWFLAKE_DIR,
    ):
        self._keys_dir: Path = keys_dir
        self._private_key: rsa.RSAPrivateKey = None
        self._public_key: rsa.RSAPublicKey = None
        self._private_key_path: Path = keys_dir.joinpath(self.PRIVATE_KEY_FILE_NAME)
        self._public_key_path: Path = keys_dir.joinpath(self.PUBLIC_KEY_FILE_NAME)
        self.root: Root = Root(session)

    @property
    def keys_dir(self):
        """The directory where the Snowflake Connection RSA keys are stored. Default ~/.snowflake."""
        return self._keys_dir

    @keys_dir.setter
    def keys_dir(self, keys_dir):
        self._keys_dir = keys_dir

    @property
    def private_key_file(self):
        """The RSA private key file."""
        return self._private_key_path

    @property
    def public_key_file(self):
        """The RSA public key file."""
        return self._public_key_path

    def __gen_key(self) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate and save the RSA KeyPair to disk."""
        try:
            # expand all dots in path ...
            keys_dir = self._keys_dir.resolve()
            self.LOGGER.debug(f"Using Keys Dir:{keys_dir}")
            keys_dir = create_secure_key_directory(keys_dir)

            # generate the keypair
            self._private_key, self._public_key = gen_key()

            passphrase = os.getenv("ENV_FILE_PASSPHRASE")
            # save the key pair
            save_key_pair(
                self._private_key,
                self._private_key_path,
                self._public_key_path,
                passphrase,
            )
            self.LOGGER.debug("Generated and saved keys")
            return (self._private_key, self._public_key)
        except Exception as e:
            self.LOGGER.error(f"Error generating key,{e}")
            raise UserKeyError(e)

    def set_or_rotate_public_key(self, snowflake_user: str) -> tuple[Path, str, bool]:
        """Generate, set or rotate the RSA public key of a Snowflake user.

        The rules for setting the keys:
        - If RSA_PUBLIC_KEY and RSA_PUBLIC_KEY_2 is not set for user then set as RSA_PUBLIC_KEY
        - If RSA_PUBLIC_KEY is set then the key is rotated to RSA_PUBLIC_KEY_2 and vice versa

        Args:
            snowflake_user (str): The Snowflake username to set/rotate keys for

        Returns:
            tuple: Contains:
                - Path: the generated keypath
                - str: the public key fingerprint
                - bool: whether the key was rotated or not

        See Also:
            For more details on Snowflake key pair authentication:
            - https://docs.snowflake.com/en/user-guide/key-pair-auth
            - https://docs.snowflake.com/en/user-guide/key-pair-auth#configuring-key-pair-rotation

        """
        _, pub_key = self.__gen_key()
        user: User = self.root.users[snowflake_user].fetch()
        is_rotated = False
        rotated: str = "one"
        pub_key_str = save_public_key(
            pub_key,
            filename=None,
        )

        if user.rsa_public_key is None and user.rsa_public_key_2 is None:
            self.LOGGER.debug(f"Setting RSA Public Key for user {snowflake_user}")
            user.rsa_public_key = pub_key_str
        elif user.rsa_public_key is not None:
            is_rotated = True
            self.LOGGER.debug(
                f"Rotating 1 to 2 RSA Public Key for user {snowflake_user}"
            )
            user.rsa_public_key_2 = pub_key_str
            user.rsa_public_key = None
            rotated = "two"
        elif user.rsa_public_key_2 is not None:
            is_rotated = True
            self.LOGGER.debug(
                f"Rotating 2 to 1 RSA Public Key for user {snowflake_user}"
            )
            user.rsa_public_key = pub_key_str
            user.rsa_public_key_2 = None

        try:
            self.root.users[snowflake_user].create_or_alter(user)
            # fetch the user and send details for verification and checks
            user: User = self.root.users[snowflake_user].fetch()
        except Exception as e:
            self.LOGGER.error(
                f"Error altering user,{e}", exc_info=True, stack_info=True
            )
            raise UserKeyError(e)
        self.LOGGER.debug(f"User {snowflake_user} update successful.")
        # fetch the user and send details for verification and checks
        user: User = self.root.users[snowflake_user].fetch()
        return (
            self._public_key_path,
            user.rsa_public_key_fp if rotated == "one" else user.rsa_public_key_2_fp,
            is_rotated,
        )
