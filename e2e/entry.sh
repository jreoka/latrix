#!/bin/bash
set -euo pipefail
mkdir -p /root/.ssh /run/sshd
chmod 700 /root/.ssh
cp /keys/id.pub /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
rm -f /var/run/docker.pid /var/run/docker/containerd/containerd.pid
wireguard-go latrix0
dockerd >/var/log/dockerd.log 2>&1 &
DOCKERD_PID=$!
for _ in $(seq 1 30); do
  docker info >/dev/null 2>&1 && break
  sleep 1
done
docker load -i /images/images.tar >/dev/null
# Start sshd only after dockerd and preloaded images are ready so e2e runs don't race.
/usr/sbin/sshd
trap 'kill "$DOCKERD_PID" 2>/dev/null || true; exit 0' TERM INT
sleep infinity &
wait $!
