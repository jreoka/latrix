#!/usr/bin/env bash
set -euo pipefail
docker ps -aq --filter name='^vps[0-9]+$' | xargs -r docker rm -f >/dev/null 2>&1 || true
docker network rm vpsnet >/dev/null 2>&1 || true
rm -rf /tmp/latrix-e2e
