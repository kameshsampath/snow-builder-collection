"""Configure Snowflake config.toml with connection settings using the RSA keys."""

import stat
from pathlib import Path

import tomli_w as toml_writer

from log.logger import get_logger as logger
from security.util.user_util import UserUtil


class InvalidConnectionConfigError(BaseException):
    """Raised when a invalid configuration details are provided."""

    def __init__(self, *args):  # noqa: D107
        super().__init__(*args)


class ConnectionConfig:
    """ConnectionConfig is  used to generate the `config.toml` using the RSA keypair."""

    LOGGER = logger("connection_config")

    def __init__(
        self,
        config_dir: Path | None,
        snowflake_account: str | None,
        snowflake_user: str | None,
        private_key_path: Path | None,
        default_connection_name: str | None,
        default_role: str | None,
        default_warehouse: str | None,
    ):
        """Build a new ConnectionConfig."""
        self._default_connection_name = default_connection_name
        self._default_role = default_role
        self._default_warehouse = default_warehouse
        self._config_dir = config_dir
        self._snowflake_account = snowflake_account
        self._snowflake_user = snowflake_user
        if private_key_path is None:
            self._private_key_path = self._config_dir.joinpath(
                UserUtil.private_key_file
            )
        else:
            self._private_key_path = private_key_path

    def write_config(self):
        """Write the Snowflake connection configuration."""
        str_pk_file_path = str(self._private_key_path.resolve())
        connection_default = {
            "default": {
                "account": self._snowflake_account,
                "user": self._snowflake_user,
                "private_key_file": str_pk_file_path,
                "private_key_path": str_pk_file_path,
                "role": self._default_role,
                "warehouse": self._default_warehouse,
                "authenticator": "SNOWFLAKE_JWT",
            }
        }
        doc = {
            "default_connection_name": self._default_connection_name,
            "connections": connection_default,
        }
        config_path = self._config_dir.joinpath("config.toml")
        self.LOGGER.debug(f"Snowflake Config file path {config_path}")
        try:
            self.LOGGER.debug(f"Configuration:\n{toml_writer.dumps(doc)}")
            with Path.open(config_path, "wb") as f:
                toml_writer.dump(doc, f)
        except Exception as e:
            self.LOGGER.error(
                f"Error writing configuration,{e}",
                exc_info=True,
            )
            raise (InvalidConnectionConfigError(e))

        config_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
