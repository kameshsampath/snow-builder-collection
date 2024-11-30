import os
from jinja2 import Environment, FileSystemLoader
import stat
from pathlib import Path
from typing import Union
from log.logger import get_logger as logger

from typing import Optional


class ConnectionConfig:
    LOGGER = logger("connection_config")

    def __init__(
        self,
        keys_dir: Optional[Path],
        snowflake_account: Optional[str],
        snowflake_user: Optional[str],
        private_key_path: Optional[Path],
        connection_name: Optional[str],
        default_role: Optional[str],
        warehouse: Optional[str],
    ):
        self._connection_name = connection_name
        self._default_role = default_role
        self._warehouse = warehouse
        self._keys_dir = keys_dir
        self._snowflake_account = snowflake_account
        self._snowflake_user = snowflake_user
        if private_key_path is None:
            self._private_key_path = keys_dir.joinpath("snowflake_user.p8")
        else:
            self._private_key_path = private_key_path
        curr_path = Path(os.path.dirname(__file__))
        self._template_dir = curr_path.joinpath(
            "..",
            "templates",
        )
        # make the absolute path
        self._template_dir = self._template_dir.resolve()
        self.LOGGER.debug(f"Template Dir:{self._template_dir}")
        self._template_name = "config.toml.j2"
        self._template_env = Environment(loader=FileSystemLoader(self._template_dir))
        self._template = self._template_env.get_template(self._template_name)

    def write_config(self):
        str = self._template.render(
            {
                "connection_name": self._connection_name,
                "account": self._snowflake_account,
                "user": self._snowflake_user,
                "private_key_file": self._private_key_path.resolve(),
                "default_role": self._default_role,
                "warehouse": self._warehouse,
            }
        )
        config_path = self._keys_dir.joinpath("config.toml")
        self.LOGGER.debug(f"Snowflake Config file path {config_path}")
        with Path.open(config_path, "w") as f:
            f.write(str)
            f.flush()
        config_path.chmod(stat.S_IRUSR | stat.S_IWUSR)
