#!/usr/bin/env bash
# Simulate a cluster of N "servers" with Docker so you can try latrix's
# multi-machine features (mesh, failover, drains, volume moves, updates)
# without paying for VPSes. Each container has sshd, its own Docker daemon
# and userspace WireGuard. Needs a Linux host with Docker.
#
#   e2e/up.sh 3
#   export LATRIX_CONFIG=/tmp/latrix-e2e/config.toml
#   latrix machine add root@172.30.0.11 --name m1 -i /tmp/latrix-e2e/id
#   latrix machine add root@172.30.0.12 --name m2 -i /tmp/latrix-e2e/id
#   ...then deploy, and `docker kill vps1` to watch a failover.
#
#   e2e/down.sh       # remove everything
set -euo pipefail
N="${1:-3}"
if ! [[ "$N" =~ ^[0-9]+$ ]] || [ "$N" -lt 1 ] || [ "$N" -gt 200 ]; then
  echo "usage: $0 [N]   (N must be between 1 and 200)" >&2
  exit 1
fi
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK=/tmp/latrix-e2e
mkdir -p "$WORK/keys" "$WORK/images"
[ -f "$WORK/id" ] || ssh-keygen -q -t ed25519 -N '' -f "$WORK/id"
cp "$WORK/id.pub" "$WORK/keys/id.pub"
docker build -q -t latrix-test-vps "$HERE" >/dev/null
# Preload images so the nested Docker daemons don't need registry access.
docker pull -q registry:2 >/dev/null && docker pull -q busybox:1.36 >/dev/null
docker save registry:2 busybox:1.36 -o "$WORK/images/images.tar"
docker network create --subnet 172.30.0.0/24 vpsnet >/dev/null 2>&1 || true
for i in $(seq 1 "$N"); do
  ip="172.30.0.$((10 + i))"
  docker rm -f "vps$i" >/dev/null 2>&1 || true
  docker run -d --name "vps$i" --hostname "vps$i" --privileged --network vpsnet --ip "$ip" \
    -v "$WORK/keys:/keys:ro" -v "$WORK/images:/images:ro" latrix-test-vps >/dev/null
  # Fresh containers get fresh SSH host keys at the same IPs.
  ssh-keygen -R "$ip" >/dev/null 2>&1 || true
  echo "vps$i: root@$ip"
done
echo "ssh key: $WORK/id   (use: export LATRIX_CONFIG=$WORK/config.toml)"
