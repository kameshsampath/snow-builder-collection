FROM python:3.11-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y gcc g++ direnv httpie  \
    &&  useradd -m -r -G root --shell /usr/bin/bash me \
    && rm -rf /var/lib/apt/lists/*

ADD requirements.txt /requirements.txt
ADD constraints.txt /constraints.txt

USER me

ENV HOME=/home/me
ENV SNOWFLAKE_HOME="${HOME}/.snowflake"
ENV PATH="=${HOME}/.local/bin:${PATH}"

RUN pip install --no-cache-dir --user -U pip  \
    && pip install --no-cache-dir --user  -r /requirements.txt

RUN mkdir -p "${HOME}/{.snowflake,app}"


WORKDIR ${HOME}/app

CMD ["python"]