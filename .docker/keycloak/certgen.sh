#!/bin/sh
set -eu

apk add --no-cache openssl >/dev/null

if [ ! -s /certs/ca.crt ] || [ ! -s /certs/keycloak.crt ] || [ ! -s /certs/keycloak.key ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -subj '/CN=Warden E2E CA' \
    -keyout /certs/ca.key \
    -out /certs/ca.crt
  openssl req -newkey rsa:2048 -nodes \
    -subj '/CN=keycloak' \
    -keyout /certs/keycloak.key \
    -out /certs/keycloak.csr
  printf '%s\n' \
    'basicConstraints=CA:FALSE' \
    'keyUsage=digitalSignature,keyEncipherment' \
    'extendedKeyUsage=serverAuth' \
    'subjectAltName=DNS:keycloak' > /certs/keycloak.ext
  openssl x509 -req -days 2 \
    -in /certs/keycloak.csr \
    -CA /certs/ca.crt \
    -CAkey /certs/ca.key \
    -CAcreateserial \
    -extfile /certs/keycloak.ext \
    -out /certs/keycloak.crt
fi

chmod 0644 /certs/ca.crt /certs/keycloak.crt /certs/keycloak.key
