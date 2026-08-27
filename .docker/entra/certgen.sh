#!/bin/sh
set -eu

apk add --no-cache openssl >/dev/null

if [ ! -s /certs/ca.crt ] || [ ! -s /certs/entra.crt ] || [ ! -s /certs/entra.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=Warden Entra E2E CA' \
    -keyout /certs/ca.key \
    -out /certs/ca.crt
  openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=login.microsoftonline.com' \
    -keyout /certs/entra.key \
    -out /certs/entra.csr
  printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:login.microsoftonline.com' > /certs/entra.ext
  openssl x509 -req -days 2 \
    -in /certs/entra.csr \
    -CA /certs/ca.crt \
    -CAkey /certs/ca.key \
    -CAcreateserial \
    -extfile /certs/entra.ext \
    -out /certs/entra.crt
fi

chmod 0644 /certs/ca.crt /certs/entra.crt /certs/entra.key
