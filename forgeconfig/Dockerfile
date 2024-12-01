ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER me

WORKDIR /home/me

ADD --chown=me:me src/ /home/me/app/
ADD --chown=me:me scripts/bin/run /home/me/.local/bin/run
ADD --chown=me:me scripts/bin/user_key_setup /home/me/.local/bin/user_key_setup
ADD --chown=me:me requirements.txt /home/me/app/requirements.txt

RUN pip install --no-cache-dir --user -U pip  \
  && pip install --no-cache-dir --user  -r /home/me/app/requirements.txt
