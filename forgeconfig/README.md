# Snow ForgeConfig

A utility that helps manage RSA key generation and configuration for Snowflake users.

## Quickstart

1. Copy the example environment file and update it:
```shell
cp $DEMO_HOME/.env.example $DEMO/.env
```

2. Set these required environment variables:
```shell
# Application log level
APP_LOG_LEVEL=DEBUG
# Snowflake Account identifier
SNOWFLAKE_ACCOUNT=your snowflake account id
# Snowflake username
SNOWFLAKE_USER=your snowflake user name
# Snowflake user password
SNOWFLAKE_PASSWORD=your snowflake user password
# Snowflake role (needs permissions for DB/schema creation and user alterations)
SNOWFLAKE_ROLE=ACCOUNTADMIN
```

3. Encrypt the `.env` using [gpg](https://gnupg.org/)

```shell
gpg --symmetric --cipher-algo AES256 .env
```

That should generate an encrypted version of the `.env` as `.env.gpg`. The encrypted file will be add to the container. The container will then decrypt in memory use it for needed Snowflake tasks and erase it once all tasks are successful.

> [!IMPORTANT]
> Make note of the passphrase anywhere safe and pass it in the next command

4. Start the service:

```shell
cd $DEMO_HOME
echo "ENV_FILE_PASSPHRASE=$ENV_FILE_PASSPHRASE" > .env.docker
docker-compose up -e "ENV_FILE_PASSPHRASE=$ENV_FILE_PASSPHRASE" -d
```

5. Copy the generated configs to local machine:
```shell
$PROJECT_HOME/scripts/bin/docker-copy.sh
```

5. Set up Snowflake CLI to use the config:
```shell
export SNOWFLAKE_HOME=$PWD/.snowflake
snow connection test
```

## What It Does

The `config` service automatically:
- Creates an RSA KeyPair
- Configures your Snowflake user with the public key
- Generates the required `config.toml` file
- Places everything in the correct location (`/home/me/.snowflake/config.toml`)

For more information about using these configurations, see the [Snowflake CLI documentation](https://docs.snowflake.com/en/developer-guide/snowflake-cli/index).