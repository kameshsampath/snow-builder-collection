#!/bin/bash

set -euo pipefail 

docker run -v apj-build-2024-slack-demo_snowflake_home:/snowflake busybox


# Create a temporary container with the volume mounted
docker container create --name data_snowflake_config -v  apj-build-2024-slack-demo_snowflake_home:/data busybox

# Copy files from the container to your local machine
docker cp data_snowflake_config:/data .snowflake

# Remove the temporary container
docker rm data_snowflake_config

sed -i "s|/home/me|$PWD|g" .snowflake/config.toml