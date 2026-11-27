#!/bin/bash
mkdir -p /root/.ssh /run/sshd && cp /keys/id.pub /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
/usr/sbin/sshd
rm -f /var/run/docker.pid /var/run/docker/containerd/containerd.pid
wireguard-go latrix0
dockerd >/var/log/dockerd.log 2>&1 &
for i in $(seq 1 30); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker load -i /images/images.tar >/dev/null
exec sleep infinity
