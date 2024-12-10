# syntax=docker/dockerfile:1.11
ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER me

WORKDIR /home/me

ADD --chown=me:me src/ /home/me/app/
COPY scripts/bin/run /home/me/.local/bin/run
COPY scripts/bin/user_key_setup /home/me/.local/bin/user_key_setup
COPY requirements.txt /home/me/app/requirements.txt
# this is required only when the client builds the image from this base
ONBUILD COPY .env.gpg /home/me/app/.env.gpg

RUN pip install --no-cache-dir --user -U pip  \
  && pip install --no-cache-dir --user  -r /home/me/app/requirements.txt