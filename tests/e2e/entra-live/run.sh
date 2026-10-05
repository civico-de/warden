#!/usr/bin/env bash
# Live Entra ID E2E: real tenant, real login page, disposable CiviCRM.
# Run manually (never in CI). Needs: az login --tenant …, tofu, docker, node.
# Tofu creates the app registration and test user once and keeps them;
# `tofu destroy` in ./tofu removes them again.
set -euo pipefail

if [[ -z "${WARDEN_ENTRA_LIVE_TENANT:-}" ]]; then
  echo "WARDEN_ENTRA_LIVE_TENANT (Directory tenant ID) is required." >&2
  exit 2
fi
export TF_VAR_tenant_id="${WARDEN_ENTRA_LIVE_TENANT}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/../../.." && pwd)"
compose_file="${repo_dir}/.docker/docker-compose.entra-live.yml"
site_url="${WARDEN_ENTRA_LIVE_SITE_URL:-http://localhost:8087}"

cd "${script_dir}/tofu"
tofu init -input=false >/dev/null
tofu apply -input=false -auto-approve -var "site_url=${site_url}"
tenant_id="$(tofu output -raw tenant_id)"
client_id="$(tofu output -raw client_id)"
client_secret="$(tofu output -raw client_secret)"
user_principal_name="$(tofu output -raw user_principal_name)"
user_password="$(tofu output -raw user_password)"
cd "${script_dir}"

cleanup() {
  docker compose -f "${compose_file}" down --volumes --remove-orphans
}
trap cleanup EXIT

WARDEN_ENTRA_LIVE_SITE_URL="${site_url}" \
  docker compose -f "${compose_file}" up -d --wait --wait-timeout 300 app
docker compose -f "${compose_file}" exec -T -u www-data -w /var/www/html/ext/warden \
  -e "WARDEN_ENTRA_LIVE_TENANT=${tenant_id}" \
  -e "WARDEN_ENTRA_LIVE_CLIENT_ID=${client_id}" \
  -e "WARDEN_ENTRA_LIVE_CLIENT_SECRET=${client_secret}" \
  app cv scr tests/e2e/entra-live/seed.php

npm ci --ignore-scripts >/dev/null
npx playwright install chromium >/dev/null
WARDEN_ENTRA_LIVE_SITE_URL="${site_url}" \
WARDEN_ENTRA_LIVE_TENANT="${tenant_id}" \
WARDEN_ENTRA_LIVE_CLIENT_ID="${client_id}" \
WARDEN_ENTRA_LIVE_USER="${user_principal_name}" \
WARDEN_ENTRA_LIVE_PASSWORD="${user_password}" \
  npx playwright test warden-entra-live.spec.mjs

docker compose -f "${compose_file}" exec -T -u www-data -w /var/www/html/ext/warden app \
  cv scr tests/e2e/entra-live/verify.php
