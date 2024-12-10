#!/bin/bash

set -euo pipefail

DOCKER_VOL_NAME=snow_forgeconfig
CONTAINER_NAME="data_${DOCKER_VOL_NAME}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DOCKER_COMPOSE_DIR="$(dirname "$(dirname "$SCRIPT_DIR")")"
DOCKER_COMPOSE_PROJECT_NAME=$(basename "$DOCKER_COMPOSE_DIR")

docker run -v "${CONTAINER_NAME}":/snowflake busybox

# Create a temporary container with the volume mounted
# the volume name if used docker compose will be "${PWD}_<volume_name>"
docker container create --name "${CONTAINER_NAME}" -v  "${DOCKER_COMPOSE_PROJECT_NAME}_${DOCKER_VOL_NAME}":/data busybox

# Copy files from the container to your local machine
# remove the existing  ``.snowflake` directory
if [ -d "${PWD}/.snowflake" ]; then
  rm -r "${PWD}/.snowflake"
fi

docker cp "${CONTAINER_NAME}":/data "${PWD}/.snowflake"

# Remove the temporary container
docker rm "${CONTAINER_NAME}"

sed -i "s|/home/me|$PWD|g" "${PWD}/.snowflake/config.toml"
