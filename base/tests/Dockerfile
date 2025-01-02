FROM ghcr.io/kameshsampath/snow-builder-collection/snow-base:dev

USER me

WORKDIR /app

COPY test.env.gpg /app/.env.gpg

COPY entrypoint.py /entrypoint

ENTRYPOINT [ "/entrypoint" ]