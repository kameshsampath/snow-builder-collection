#!/usr/bin/env python3

# %%
# Imports
import os
from contextlib import contextmanager
from io import StringIO
from pathlib import Path

from dotenv import dotenv_values
from gnupg import GPG, Crypt


# %%
# Define Temp Env
@contextmanager
def temp_env(_encrypted_env_file: Path | str = "/app/.env.gpg"):
    """Decrypt the encrypted env file using.

    Build a temporary context using the environment variables loaded from the encrypted
    env file in-memory and yield context with those values. Once the context exists the
    environment variables are erased from the memory.

    Args:
    _encrypted_env_file: the encrypted env file to decrypt. Defaults to `/app/.env.gpg`

    ValueError: When the passphrase is empty

    """
    __passphrase = os.getenv("ENV_FILE_PASSPHRASE")

    if isinstance(__passphrase, str):
        gpg = GPG()
        out: Crypt = gpg.decrypt_file(
            str(_encrypted_env_file),
            passphrase=__passphrase,
        )
        config = StringIO(bytes.decode(out.data))

        env_vars: dict[str, str] = dotenv_values(stream=config)
        original_env: dict[str, str] = {
            key: os.getenv(key) for key in env_vars if env_vars[key] is not None
        }

        assert original_env is not None, f"{original_env} is empty"

        try:
            # Set new values
            {
                os.environ.__setitem__(key, value)
                for key, value in env_vars.items()
                if value is not None
            }
            yield

        finally:
            # Restore original state using dict comprehension
            {
                os.environ.pop(key, None)
                if value is None
                else os.environ.__setitem__(key, value)
                for key, value in original_env.items()
            }
    else:
        raise ValueError(f"Passphrase required.'{__passphrase}' is empty")


# %%
# Check in and out of context
with temp_env():
    assert (
        os.getenv("FOO") == "BAR"
    ), "Expect the environment variable 'FOO' to be 'BAR'. "

assert os.getenv("FOO") is None, "Expecting the environment variable 'FOO' to be None."

# %%
