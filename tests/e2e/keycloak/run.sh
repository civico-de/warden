#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/../../.." && pwd)"
compose_file="${repo_dir}/.docker/docker-compose.keycloak.yml"

cleanup() {
  local status=$?
  # On failure, show why before the teardown removes the containers: app and db
  # output only, never the stack's environment.
  if [ "${status}" -ne 0 ]; then
    docker compose -f "${compose_file}" ps -a || true
    docker compose -f "${compose_file}" logs --no-color --timestamps --tail 300 app db || true
  fi
  docker compose -f "${compose_file}" down --volumes --remove-orphans
}
trap cleanup EXIT

docker compose -f "${compose_file}" up -d --wait --wait-timeout 300 app keycloak
docker compose -f "${compose_file}" exec -T -u www-data -w /var/www/html/ext/warden app \
  cv scr tests/e2e/keycloak/seed.php
docker compose -f "${compose_file}" exec -T -u www-data -w /var/www/html/ext/warden app \
  vendor/bin/phpunit -c phpunit.xml.dist
docker compose -f "${compose_file}" run --rm playwright
