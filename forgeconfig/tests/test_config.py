"""Tests for Connection Config Generator."""

import tomllib
from pathlib import Path

import pytest

from connection.config import ConnectionConfig
from security.rsa.keypair_generator import create_secure_key_directory


@pytest.fixture(scope="module")
def config_dir():  # noqa: D103
    _config_dir = Path.joinpath(Path.cwd(), "tests", "keys")
    _config_dir = create_secure_key_directory(_config_dir)

    yield _config_dir
    # cleanup after tests
    for f in _config_dir.iterdir():
        if f.is_file():
            Path.unlink(f)
    Path.rmdir(_config_dir)


def test_defaults(config_dir):  # noqa: D103
    want = tomllib.loads(f"""
default_connection_name = "default"

[connections.default]
account = "dummy-account"
authenticator = "SNOWFLAKE_JWT"
private_key_file = "{config_dir}/snowflake_user.p8"
private_key_path = "{config_dir}/snowflake_user.p8"
role = "ACCOUNTADMIN"
user = "snowflake-user"
warehouse = "COMPUTE_WH"
""")
    connection_config = ConnectionConfig(
        config_dir=config_dir,
        snowflake_account="dummy-account",
        snowflake_user="snowflake-user",
        private_key_path=config_dir.joinpath("snowflake_user.p8"),
        default_connection_name="default",
        default_role="ACCOUNTADMIN",
        default_warehouse="COMPUTE_WH",
    )
    connection_config.write_config()
    config_file = config_dir.joinpath("config.toml")
    assert config_file.exists() is True
    with Path.open(config_file, "rb") as f:
        got = tomllib.load(f)

    assert got is not None
    assert want == got
