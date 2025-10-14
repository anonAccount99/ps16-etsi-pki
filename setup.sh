#!/usr/bin/env bash
set -euo pipefail
mkdir -p benchmark-results
if command -v id >/dev/null 2>&1; then
  UID_VAL="$(id -u)"
  GID_VAL="$(id -g)"
else
  UID_VAL="1000"
  GID_VAL="1000"
fi
{
  echo "UID=${UID_VAL}"
  echo "GID=${GID_VAL}"
  if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    echo "SELINUX_LABEL=:Z"
  else
    echo "SELINUX_LABEL="
  fi
} > .env
chown -R 1001:1001 benchmark-results
chmod -R u+rwX,g+rwX benchmark-results || true
