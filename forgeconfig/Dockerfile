# syntax=docker/dockerfile:1.11
ARG BASE_IMAGE=ghcr.io/kameshsampath/snow-builder-collection/snow-base:py-311
FROM ${BASE_IMAGE}

USER me

WORKDIR /home/me

ADD --chown=me:me src/ /home/me/app/
COPY scripts/bin/run /home/me/.local/bin/run
COPY requirements.txt /home/me/app/requirements.txt
# this is required only when the client builds the image from this base
ONBUILD COPY .env.gpg /home/me/app/.env.gpg

RUN pip install --no-cache-dir --user -U pip  \
  && pip install --no-cache-dir --user  -r /home/me/app/requirements.txt

ENV PYTHONPATH="/home/me/app:${PYTHONPATH}"
ENV ENV_FILE="/home/me/app/.env.gpg"