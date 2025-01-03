#!/usr/bin/env python3
"""Run the Snowflake User setup."""

import os
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from snowflake.core import Root
from snowflake.core.user import User
from snowflake.snowpark.session import Session

from connection.config import ConnectionConfig
from log.logger import get_logger
from security.util.rsa_key_util import (
    get_key_fingerprint,
    load_rsa_public_key,
    match_fingerprints,
)
from security.util.user_util import UserUtil

#
logger = get_logger("user_key_setup")


class UserSetupUtil:
    """The utility used to setup the Snowflake user with the Keys."""

    def __init__(  # noqa: D107
        self,
        target_snowflake_account: str,
        target_snowflake_user: str,
        target_snowflake_default_role: str | None = "PUBLIC",
        target_snowflake_default_wh: str | None = "COMPUTE_WH",
    ):
        self._target_snowflake_account = target_snowflake_account
        self._target_snowflake_user = target_snowflake_user
        self._snowflake_role = target_snowflake_default_role
        self._snowflake_warehouse = target_snowflake_default_wh
        self._keys_dir: Path = Path(
            os.getenv("PRIVATE_KEY_FILE_DIR", Path.home().joinpath(".snowflake"))
        )
        self._config_dir = self._keys_dir
        self._private_key_passphrase = os.getenv("PRIVATE_KEY_PASSPHRASE", None)
        self.session = None

    @contextmanager
    def temporary_env_var(self, variables: dict[str, Any]) -> None:
        """Context manager for temporarily setting environment variables.

        Automatically restores the original state when exiting the context.

        Args:
        variables: Dictionary of environment variables and their values to set.

        Example:
          with temporary_env_var({"API_KEY": "secret", "DEBUG": "1"}):
              # Code that needs these environment variables
              pass
          # Variables are automatically unset here

        """
        # Store the original state of variables
        original_state: dict[str, str | None] = {}

        try:
            # Save original values and set new ones
            for key, value in variables.items():
                # Store the original value (or None if it didn't exist)
                original_state[key] = os.environ.get(key)

                # Set the new value, converting to string if necessary
                os.environ[key] = str(value)

            yield  # Allow the context block to execute

        finally:
            # Restore original state, whether or not an exception occurred
            for key, original_value in original_state.items():
                if original_value is None:
                    # Variable didn't exist originally, so remove it
                    os.environ.pop(key, None)
                else:
                    # Restore the original value
                    os.environ[key] = original_value

    def generate_and_set_rsa_keys(self, rotate: bool = False) -> tuple[Path, str, bool]:
        """Generate RSA keypair and configure the RSA key authentication with Snowflake USER.

        Args:
        rotate: Flag to rotate the keys

        Returns:
            A tuple
              - Path - the path of the generated key path
              - str - the public key fingerprint
              - bool- whether the key was rotated

        """
        self._pk_file = self._keys_dir.joinpath("snowflake_user.p8")
        self._pub_file = self._keys_dir.joinpath("snowflake_user.pub")
        if (
            not rotate
            and (self._keys_dir.exists() and self._keys_dir.is_dir())
            and (self._pk_file.exists() and self._pk_file.is_file())
            and (self._pub_file.exists() and self._pub_file.is_file())
        ):
            logger.info("KeyPair exists and configured, skip creation.")
            pub_key = load_rsa_public_key(self._pub_file)
            fp = get_key_fingerprint(pub_key)
            return (
                self._pub_file,
                fp,
                False,
            )
        else:
            logger.info("Generating KeyPair")
            self.session = Session.builder.configs(
                {
                    "account": os.getenv("SNOWFLAKE_ACCOUNT"),
                    "user": os.getenv("SNOWFLAKE_USER"),
                    "password": os.getenv("SNOWFLAKE_PASSWORD"),
                    "role": os.getenv("SNOWFLAKE_ROLE", "SECURITYADMIN"),
                }
            ).getOrCreate()

            user_util = UserUtil(
                self.session,
                self._keys_dir,
            )
            return user_util.set_or_rotate_public_key(self._target_snowflake_user)

    def create_or_update_config(self, default_connection_name: str):
        """Generate the Snowflake Connection configuration.

        Args:
        default_connection_name: The connection name to use, if None it defaults to `default`.

        """
        conn_config = ConnectionConfig(
            config_dir=self._config_dir,
            snowflake_account=self._target_snowflake_account,
            snowflake_user=self._target_snowflake_user,
            private_key_path=self._pk_file,
            default_connection_name=default_connection_name,
            default_role=self._snowflake_role,
            default_warehouse=self._snowflake_warehouse,
        )
        conn_config.write_config()

    def verify_keys_and_settings(self, public_key_fp: str, connection_name: str):
        """Run a sanity check to verify if the user able to connect.

        Args:
        public_key_fp: the public key fingerprint to verify with user settings.
        connection_name: The connection name to use, if None it defaults to `default`.

        """
        logger.debug(
            f"Verifying connection with new public key for user {self._target_snowflake_user}"
        )
        with self.temporary_env_var(
            {"SNOWFLAKE_HOME": str(self._config_dir.resolve().absolute())}
        ):
            try:
                _session = Session.builder.configs(
                    {
                        "connection_name": connection_name,
                        "private_key_file_pwd": os.getenv("ENV_FILE_PASSPHRASE"),
                    }
                ).create()
                root = Root(_session)
                user: User = root.users[self._target_snowflake_user].fetch()
                # logger.debug(f"Fetched user:{user.__dict__}")
                # should match either rsa_public_key or rsa_public_key2
                # strip SHA256:
                _key_fp_1 = user.rsa_public_key_fp and match_fingerprints(
                    public_key_fp, user.rsa_public_key_fp.replace("SHA256:", "")
                )
                if _key_fp_1:
                    logger.debug(
                        f"Fingerprints '{public_key_fp}' == '{user.rsa_public_key_fp.replace('SHA256:', '')}' matches."
                    )
                _key_fp_2 = user.rsa_public_key_2_fp and match_fingerprints(
                    public_key_fp, user.rsa_public_key_2_fp.replace("SHA256:", "")
                )
                if _key_fp_2:
                    logger.debug(
                        f"Fingerprints '{public_key_fp}' == '{user.rsa_public_key_2_fp.replace('SHA256:', '')}' matches."
                    )
                if _key_fp_1 and _key_fp_2:
                    logger.error(
                        f"Fingerprints mismatch,{public_key_fp} != {user.rsa_public_key_fp}\n\n or {public_key_fp} != {user.rsa_public_key_2_fp}"
                    )
                    return
                logger.info("Fingerprints matches!")

                logger.debug(
                    f"Using Snowflake home:{os.getenv('SNOWFLAKE_HOME')}, connection_name:{connection_name}"
                )
                logger.info("User keys configured and verified successfully.")
            except Exception as e:
                logger.error(f"Error verifying, {e}", stack_info=True)
                raise e
            finally:
                if _session is not None:
                    _session.close()
                if self.session is not None:
                    self.session.close()

    @staticmethod
    def run(
        target_snowflake_account: str,
        target_snowflake_user: str,
        target_snowflake_default_role: str,
        target_snowflake_default_wh: str,
        default_connection_name: str,
        rotate: bool,
    ):  # noqa: D103
        """Trigger the Key generation and user configuration tasks."""
        logger.info("Good to run the Snowflake user configuration.")
        user_util = UserSetupUtil(
            target_snowflake_account=target_snowflake_account,
            target_snowflake_user=target_snowflake_user,
            target_snowflake_default_role=target_snowflake_default_role,
            target_snowflake_default_wh=target_snowflake_default_wh,
        )
        _, public_key_fp, _ = user_util.generate_and_set_rsa_keys(rotate)
        user_util.create_or_update_config(default_connection_name)
        user_util.verify_keys_and_settings(public_key_fp, default_connection_name)
