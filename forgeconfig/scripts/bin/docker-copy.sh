#!/bin/bash

set -euo pipefail

DOCKER_VOL_NAME="$(docker compose config --volumes)"
CONTAINER_NAME="data_${DOCKER_VOL_NAME}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_COMPOSE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
DOCKER_COMPOSE_PROJECT_NAME=$(basename "$DOCKER_COMPOSE_DIR")

docker run -v "${CONTAINER_NAME}":/snowflake busybox > /dev/null 2>&1

# Create a temporary container with the volume mounted
# the volume name if used docker compose will be "${PWD}_<volume_name>"
docker container create --name "${CONTAINER_NAME}" \
  -v  "${DOCKER_COMPOSE_PROJECT_NAME}_${DOCKER_VOL_NAME}":/data busybox \
  > /dev/null 2>&1

# Copy files from the container to your local machine
docker cp "${CONTAINER_NAME}":/data "${PWD}/.snowflake" > /dev/null 2>&1

# Remove the temporary container
docker rm "${CONTAINER_NAME}" > /dev/null 2>&1

sed -i "s|/home/me|$PWD|g" "${PWD}/.snowflake/config.toml"

printf "Configuration successfully copied to %s\n" "$PWD/.snowflake"
