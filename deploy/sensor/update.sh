#!/usr/bin/env bash
# Pull new sensor images and recreate the containers.
# Egress is locked down, so this opens a short `setup` window to reach the
# registry, then locks down again (even on failure).
set -euo pipefail
cd "$(dirname "$0")"
trap 'honeypot-firewall lockdown --no-rollback' EXIT
honeypot-firewall setup --no-rollback
docker compose pull --ignore-buildable
docker compose up -d --no-build --force-recreate --remove-orphans
docker image prune -f
docker compose ps
