#!/bin/bash 
set -e
set -o pipefail

DECRYPT_CMD="gpg --quiet --batch --yes --decrypt --passphrase $ENV_FILE_PASSPHRASE /app/.env.gpg"

# Export the decrypted environment variables
eval "$($DECRYPT_CMD | sed 's/^/export /')"

echo "Foo is $FOO"

# do some process
sleep .10
# Unset variables after 10 seconds in the background
eval "$($DECRYPT_CMD | cut -d= -f1 | sed 's/^/unset /')"

sudo unset_passphrase && cat /etc/bash.bashrc 

[ -n "${FOO}" ] && printf "\n Foo is %s" "$FOO" || printf "\nFOO is not set or unset"
