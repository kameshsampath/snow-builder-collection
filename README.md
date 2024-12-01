# Snow Builder Collection

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE) [![Build Snow Base](https://github.com/kameshsampath/snow-builder-collection/actions/workflows/snow-base.yml/badge.svg)](https://github.com/kameshsampath/snow-builder-collection/actions/workflows/snow-base.yml) [![Build Snow ForgeConfig](https://github.com/kameshsampath/snow-builder-collection/actions/workflows/snow-forgeconfig.yml/badge.svg)](https://github.com/kameshsampath/snow-builder-collection/actions/workflows/snow-forgeconfig.yml)

A curated collection of containerized tools and utilities designed to enhance the Snowflake Builder experience. This repository aims to streamline common development tasks, automate configurations, and provide standardized environments for Snowflake development.

## What's Inside

- `base`: A standardized Python development container with common Snowflake packages and utilities
- `forgeconfig`: Automated RSA key generation and configuration management for Snowflake users

## Purpose

This collection exists to provide consistent development environments, automate repetitive setup tasks, streamline security configurations, reduce development overhead, and share best practices through code.

## Target Audience

Built by Builders, for Builders working with Snowflake data platforms.

## Getting Started

### Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [Snowflake Trial Account](https://signup.snowflake.com/)

### Verification Steps

- Verify Docker installation:
   ```bash
   docker --version
   ```

- Confirm Docker is running:
   ```bash
   docker ps
   ```

- Log into your Snowflake account and confirm you can access the web interface

### Component Usage

#### Base Container

The [base](./base) container provides a standardized Python development environment for Snowflake projects. 

> [!NOTE]
> Documentation coming soon.

#### Forgeconfig

The [forgeconfig](./forgeconfig/README.md) utility helps manage RSA key generation and configuration for Snowflake users. 

## References

- [Docker Desktop Installation Guide](https://docs.docker.com/desktop/)
- [Snowflake Documentation](https://docs.snowflake.com/)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.