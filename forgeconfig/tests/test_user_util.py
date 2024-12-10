"""Tests for updating the User with Keys."""

import os
from io import StringIO
from pathlib import Path

import pytest
from dotenv import load_dotenv
from gnupg import GPG, Crypt
from snowflake.core import Root
from snowflake.core.user import User
from snowflake.snowpark.session import Session

from log.logger import get_logger as _logger
from security.rsa.keypair_generator import create_secure_key_directory
from security.util.rsa_key_util import get_key_fingerprint, load_rsa_public_key
from security.util.user_util import UserUtil

logger = _logger("user_update_tests")


@pytest.fixture(scope="module")
def load_snowflake_env():
    """Decrypt and Load into memory."""
    _encrypted_env_file = (
        Path(__file__).parent.resolve().joinpath("..", ".env.gpg").resolve().absolute()
    )
    # IMPORTANT: require gpg installed locally
    gpg = GPG()
    out: Crypt = gpg.decrypt_file(
        str(_encrypted_env_file),
        passphrase=os.getenv(
            "ENV_FILE_PASSPHRASE",
        ),
    )
    config = StringIO(bytes.decode(out.data))
    if load_dotenv(stream=config):
        logger.info("Loaded environment successfully")


@pytest.fixture(scope="module")
def session(load_snowflake_env):  # noqa: D103
    session = Session.builder.configs(
        {
            "account": os.getenv("SNOWFLAKE_ACCOUNT"),
            "user": os.getenv("SNOWFLAKE_USER"),
            "password": os.getenv("SNOWFLAKE_PASSWORD"),
            "role": "ACCOUNTADMIN",
        }
    ).create()

    yield session
    logger.info("Close session")
    session.close()


@pytest.fixture(scope="module")
def root(session: Session):  # noqa: D103
    return Root(session)


@pytest.fixture(scope="module")
def snowflake_user(root: Root):  # noqa: D103
    user_name = "dummy_tester"
    user: User = User(name=user_name)
    root.users[user_name].create_or_alter(user=user)
    logger.info(f"Created dummy user {user.name}.")
    yield user
    logger.info("Dropping test user")
    root.users[user_name].drop(if_exists=True)


@pytest.fixture(scope="module")
def keys_dir():  # noqa: D103
    _keys_dir = Path(__file__).parent.resolve().joinpath("keys")
    _keys_dir = create_secure_key_directory(_keys_dir)

    yield _keys_dir
    # cleanup after tests
    for f in _keys_dir.iterdir():
        if f.is_file():
            Path.unlink(f)
    Path.rmdir(_keys_dir)


@pytest.fixture(scope="module")
def user_util(keys_dir, session):  # noqa: D103
    user_util = UserUtil(session=session, keys_dir=keys_dir)
    return user_util


def test_add_public_key(user_util, root, snowflake_user: User):  # noqa: D103
    public_key_path, fp, is_rotated = user_util.set_or_rotate_public_key(
        snowflake_user.name
    )

    want = get_key_fingerprint(load_rsa_public_key(public_key_path))

    assert public_key_path is not None
    assert fp is not None
    assert is_rotated is False

    _user = root.users[snowflake_user.name].fetch()
    assert _user.rsa_public_key is not None
    # ensure no rotation
    assert _user.rsa_public_key_2 is None
    got = _user.rsa_public_key_fp.replace("SHA256:", "")
    assert want == got, f"Fingerprint wanted {want} but got {got}"


def test_add_public_key_rotate_2(user_util, root, snowflake_user: User):  # noqa: D103
    public_key_path, fp, is_rotated = user_util.set_or_rotate_public_key(
        snowflake_user.name
    )

    want = get_key_fingerprint(load_rsa_public_key(public_key_path))

    assert public_key_path is not None
    assert fp is not None
    assert is_rotated is True

    _user = root.users[snowflake_user.name].fetch()
    assert _user.rsa_public_key is None
    # ensure no rotation
    assert _user.rsa_public_key_2 is not None
    got = _user.rsa_public_key_2_fp.replace("SHA256:", "")
    assert want == got, f"Fingerprint wanted {want} but got {got}"


def test_add_public_key_rotate_1(user_util, root, snowflake_user: User):  # noqa: D103
    public_key_path, fp, is_rotated = user_util.set_or_rotate_public_key(
        snowflake_user.name
    )

    want = get_key_fingerprint(load_rsa_public_key(public_key_path))

    assert public_key_path is not None
    assert fp is not None
    assert is_rotated is True

    _user = root.users[snowflake_user.name].fetch()
    assert _user.rsa_public_key is not None
    # ensure no rotation
    assert _user.rsa_public_key_2 is None
    got = _user.rsa_public_key_fp.replace("SHA256:", "")
    assert want == got, f"Fingerprint wanted {want} but got {got}"
