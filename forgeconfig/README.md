# Snow ForgeConfig

A utility that helps manage RSA key generation and configuration for Snowflake users.

## Quickstart

Navigate to the directory,

```shell
cd "$PROJECT_HOME/forgeconfig"
```

1. Copy the example environment file and update it:
```shell
cp $DEMO_HOME/.env.example $DEMO/.env
```

2. Set these required environment variables:
```shell
# Snowflake Account identifier
SNOWFLAKE_ACCOUNT=your snowflake account id
# Snowflake username
SNOWFLAKE_USER=your snowflake user name
# Snowflake user password
SNOWFLAKE_PASSWORD=your snowflake user password
# Snowflake role (needs permissions for DB/schema creation and user alterations)
SNOWFLAKE_ROLE=ACCOUNTADMIN
# Snowflake Account identifier of the user for whom the keys will be generated
TARGET_SNOWFLAKE_ACCOUNT=the snowflake user account for which the key need to be added
# Snowflake user name of the user
TARGET_SNOWFLAKE_USER=the snowflake user id for which the key need to be added
```

3. Encrypt the `.env` using [gpg](https://gnupg.org/)

```shell
gpg --symmetric --cipher-algo AES256 .env
```

That should generate an encrypted version of the `.env` as `.env.gpg`. The encrypted file will be add to the container. The container will then decrypt in memory use it for needed Snowflake tasks and erase it once all tasks are successful.

> [!IMPORTANT]
>  - Make note of the passphrase anywhere safe and pass it in the next command
>  - The same passphrase will be used to encrypt the generated RSA Private key
> **TIP**: Use password generators to generate strong passwords

4. Start the service:

```shell
cd $DEMO_HOME
printf "APP_LOG_LEVEL=INFO\nENV_FILE_PASSPHRASE=%s" $ENV_FILE_PASSPHRASE > .env.docker
docker-compose up
```
> [!NOTE]
> The base container for the demo 
>

5. Copy the generated configs to local machine:
```shell
$PROJECT_HOME/scripts/bin/docker-copy.sh
```
> [!NOTE]
> Run this from directory where the docker-compose is, as the script read the `volume` name to copy
> the /home/me/.snowflake directory
>

5. Set up Snowflake CLI to use the config:
```shell
export SNOWFLAKE_HOME="$PWD/.snowflake"
export PRIVATE_KEY_PASSPHRASE="$ENV_FILE_PASSPHRASE"
snow connection test
```

## What It Does

The `config` service automatically:
- Creates an RSA KeyPair, with private key encrypted using `$ENV_FILE_PASSPHRASE`
- Configures your Snowflake user with the public key
- Generates the Snowflake `config.toml` file, with a single connection default connection named `default`
- Places everything in the correct location (`/home/me/.snowflake/config.toml`)


## References

- [RSA KeyPair](https://docs.snowflake.com/en/user-guide/key-pair-auth)
- [Snowflake CLI documentation](https://docs.snowflake.com/en/developer-guide/snowflake-cli/index).