import os
import logging
from pathlib import Path
from typing import Union, Tuple
from security.rsa_keypair_generator import (
    create_secure_key_directory,
    gen_key,
    save_key_pair,
)
from snowflake.core.user import User
from security.rsa_keypair_generator import save_public_key
from snowflake.core import Root
from snowflake.snowpark.session import Session

from log.logger import get_logger as _logger


class UserKeyError(Exception):
    def __init__(self, *args):
        super().__init__(*args)


class UserUtil:
    LOGGER = _logger("user_util")

    def __init__(
        self,
        session: Session,
        keys_dir: Union[Path | str] = Path.joinpath(
            Path.home(),
            ".snowflake",
        ),
    ):
        self._keys_dir: Path = keys_dir
        self._private_key_path: Path = keys_dir.joinpath("snowflake_user.p8")
        self._public_key_path: Path = keys_dir.joinpath("snowflake_user.pub")
        self.root: Root = Root(session)

    @property
    def keys_dir(self, keys_dir):
        self._keys_dir = keys_dir

    @keys_dir.setter
    def keys_dir(self, keys_dir):
        self._keys_dir = keys_dir

    def _gen_key(self):
        try:
            # expand all dots in path ...
            keys_dir = self._keys_dir.resolve()
            self.LOGGER.debug(f"Using Keys Dir:{keys_dir}")
            keys_dir = create_secure_key_directory(keys_dir)
            self._private_key = gen_key()

            save_key_pair(
                self._private_key,
                self._private_key_path,
                self._public_key_path,
            )
            self.LOGGER.debug(f"Generated and saved keys")
        except Exception as e:
            self.LOGGER.error(f"Error generating key,{e}")
            raise UserKeyError(e)

    def set_or_rotate_public_key(self, snowflake_user: str) -> Tuple[Path, str, bool]:
        """
        Generates, sets or rotates the RSA public key of a Snowflake user

        See:
         - https://docs.snowflake.com/en/user-guide/key-pair-auth
        """
        self._gen_key()
        user: User = self.root.users[snowflake_user].fetch()
        is_rotated = False
        ## TODO do we need to set the other one to None to allow rotation ?
        if user.rsa_public_key is None:
            self.LOGGER.debug(f"Setting RSA Public Key for user {snowflake_user}")
            user.rsa_public_key = save_public_key(
                self._private_key.public_key(),
                filename=None,  # just returns the as string w/o new lines and BEGIN..END..
            )
        else:
            is_rotated = True
            # https://docs.snowflake.com/en/user-guide/key-pair-auth#configuring-key-pair-rotation
            self.LOGGER.debug(f"Rotating RSA Public Key for user {snowflake_user}")
            user.rsa_public_key_2 = save_public_key(
                self._private_key.public_key(),
                filename=None,  # just returns the as string w/o new lines and BEGIN..END..
            )

        self.root.users[snowflake_user].create_or_alter(user)
        self.LOGGER.debug(f"User update successful.")
        # fetch the user and send details for verification and checks
        user: User = self.root.users[snowflake_user].fetch()
        if is_rotated:
            return (self._public_key_path, user.rsa_public_key_2_fp, is_rotated)
        else:
            return (self._public_key_path, user.rsa_public_key_fp, is_rotated)
