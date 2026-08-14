#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/../../.." && pwd)"
compose_file="${repo_dir}/.docker/docker-compose.keycloak.yml"

cleanup() {
  docker compose -f "${compose_file}" down --volumes --remove-orphans
}
trap cleanup EXIT

docker compose -f "${compose_file}" up -d --wait --wait-timeout 300 app keycloak
docker compose -f "${compose_file}" exec -T -u www-data -w /var/www/html/ext/warden app \
  cv scr tests/e2e/keycloak/seed.php
docker compose -f "${compose_file}" exec -T -u www-data -w /var/www/html/ext/warden app \
  vendor/bin/phpunit -c phpunit.xml.dist
docker compose -f "${compose_file}" run --rm playwright
