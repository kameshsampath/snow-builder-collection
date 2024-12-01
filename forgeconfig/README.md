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

3. Start the service:
```shell
cd $DEMO_HOME
docker-compose up -d
```

4. Copy the generated configs to local machine:
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