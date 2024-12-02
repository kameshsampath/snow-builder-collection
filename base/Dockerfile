ARG PYTHON_VERSION=3.11

FROM --platform=$BUILDPLATFORM golang:1.23.2-alpine AS builder

ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /build
COPY go.mod .
COPY unset_passphrase.go main.go

# Set platform-specific GOARCH and build
RUN case "$TARGETPLATFORM" in \
  "linux/amd64") export GOARCH=amd64 ;; \
  "linux/arm64") export GOARCH=arm64 ;; \
  "linux/arm/v7") export GOARCH=arm ;; \
  *) export GOARCH=amd64 ;; \
  esac && \
  CGO_ENABLED=0 GOOS=linux go build -o unset_passphrase

FROM python:$PYTHON_VERSION-slim

LABEL org.opencontainers.image.source=https://github.com/kameshsampath/snow-builder-collection.git
LABEL org.opencontainers.image.description="Base image for Snowflake Development with Snowflake Development Tools."
LABEL org.opencontainers.image.licenses=ASL-2

RUN apt-get update \
  && apt-get install --no-install-recommends -y sudo gcc g++ direnv httpie gpg  \
  &&  useradd -m -r -G root --shell /usr/bin/bash me \
  && rm -rf /var/lib/apt/lists/*

ADD requirements.txt /requirements.txt
ADD constraints.txt /constraints.txt

COPY --from=builder /build/unset_passphrase /usr/sbin/unset_passphrase

RUN chmod +x /usr/sbin/unset_passphrase \
  && echo "me ALL = NOPASSWD: /usr/sbin/unset_passphrase" >> /etc/sudoers

USER me

ENV HOME=/home/me
ENV SNOWFLAKE_HOME="${HOME}/.snowflake"
ENV PATH="${HOME}/.local/bin:${PATH}"

RUN pip install --no-cache-dir --user -U pip  \
  && pip install --no-cache-dir --user  -r /requirements.txt

RUN mkdir -p "${HOME}/.snowflake" "${HOME}/.app"

WORKDIR ${HOME}/app

CMD ["python"]