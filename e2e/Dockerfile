# Test "VPS" image for e2e/up.sh: Ubuntu + sshd + Docker + userspace WireGuard.
# Not for production — see the main README.
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    docker.io docker-buildx openssh-server wireguard-tools wireguard-go rsync iproute2 curl git ca-certificates python3 iptables procps \
    && rm -rf /var/lib/apt/lists/*
COPY systemctl /usr/local/bin/systemctl
COPY entry.sh /entry.sh
RUN sed -i 's/\r$//' /usr/local/bin/systemctl /entry.sh \
    && chmod +x /usr/local/bin/systemctl /entry.sh && mkdir -p /etc/docker \
    && echo '{"storage-driver":"vfs","insecure-registries":["10.77.0.0/16","127.0.0.0/8"],"live-restore":true}' > /etc/docker/daemon.json
CMD ["/entry.sh"]
