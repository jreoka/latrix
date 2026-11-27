#!/usr/bin/env bash
# latrix machine setup. Runs as root over SSH from `latrix machine add`.
# Idempotent: safe to run again on an already configured machine.
set -euo pipefail

log() { echo "[latrix] $*" >&2; }

if [ -r /etc/os-release ]; then . /etc/os-release; fi
ID="${ID:-unknown}"; ID_LIKE="${ID_LIKE:-}"
log "detected ${PRETTY_NAME:-$ID} ($(uname -m))"

if ! command -v systemctl >/dev/null 2>&1; then
  log "systemd is required (supported: Ubuntu, Debian, Fedora, RHEL/Rocky/Alma, openSUSE, Arch)"
  exit 1
fi

pm=""
for c in apt-get dnf yum zypper pacman; do
  if command -v "$c" >/dev/null 2>&1; then pm="$c"; break; fi
done

install_pkgs() {
  case "$pm" in
    apt-get) DEBIAN_FRONTEND=noninteractive apt-get install -y -q "$@" >/dev/null ;;
    dnf)     dnf install -y -q "$@" >/dev/null ;;
    yum)     yum install -y -q "$@" >/dev/null ;;
    zypper)  zypper -n -q install "$@" >/dev/null ;;
    pacman)  pacman -S --noconfirm --needed "$@" >/dev/null ;;
  esac
}

log "installing base packages (git, rsync, wireguard-tools, curl)"
case "$pm" in
  apt-get)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    install_pkgs ca-certificates curl git rsync wireguard-tools iproute2 ;;
  dnf|yum)
    install_pkgs ca-certificates curl git rsync iproute
    if ! install_pkgs wireguard-tools; then
      log "enabling EPEL for wireguard-tools"
      install_pkgs epel-release || true
      install_pkgs wireguard-tools
    fi
    install_pkgs dnf-plugins-core || true ;;
  zypper)
    zypper -n -q refresh >/dev/null || true
    install_pkgs ca-certificates curl git rsync wireguard-tools iproute2 ;;
  pacman)
    pacman -Sy --noconfirm >/dev/null
    install_pkgs ca-certificates curl git rsync wireguard-tools iproute2 ;;
  *)
    log "unsupported distribution: no apt, dnf, yum, zypper or pacman found"; exit 1 ;;
esac

if ! command -v docker >/dev/null 2>&1; then
  log "installing Docker"
  case "$pm" in
    apt-get)
      # Docker's official apt repository (Ubuntu, Debian and derivatives).
      distro="$ID"; codename="${VERSION_CODENAME:-}"
      case "$ID_LIKE" in *ubuntu*) distro=ubuntu; codename="${UBUNTU_CODENAME:-$codename}" ;; esac
      if [ "$distro" != ubuntu ] && [ "$distro" != debian ]; then distro=debian; fi
      install -m 0755 -d /etc/apt/keyrings
      if curl -fsSL "https://download.docker.com/linux/$distro/gpg" -o /etc/apt/keyrings/docker.asc \
         && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$distro $codename stable" > /etc/apt/sources.list.d/docker.list \
         && apt-get update -q >/dev/null \
         && install_pkgs docker-ce docker-ce-cli containerd.io docker-buildx-plugin; then
        :
      else
        log "Docker's repository failed; falling back to the distribution's docker.io package"
        rm -f /etc/apt/sources.list.d/docker.list
        apt-get update -q >/dev/null
        install_pkgs docker.io
        install_pkgs docker-buildx || true
      fi ;;
    dnf|yum)
      repo="centos"; [ "$ID" = "fedora" ] && repo="fedora"
      url="https://download.docker.com/linux/$repo/docker-ce.repo"
      if command -v dnf >/dev/null 2>&1; then
        dnf config-manager --add-repo "$url" >/dev/null 2>&1 \
          || dnf config-manager addrepo --from-repofile="$url" >/dev/null 2>&1 || true
      else
        yum-config-manager --add-repo "$url" >/dev/null 2>&1 || true
      fi
      install_pkgs docker-ce docker-ce-cli containerd.io docker-buildx-plugin ;;
    zypper) install_pkgs docker; install_pkgs docker-buildx || true ;;
    pacman) install_pkgs docker docker-buildx ;;
  esac
fi

# Docker daemon config: trust the mesh-internal registries, keep containers
# running across daemon restarts (package upgrades), cap log sizes.
mkdir -p /etc/docker
daemon=/etc/docker/daemon.json
changed=0
if [ ! -s "$daemon" ]; then
  cat > "$daemon" <<'JSON'
{
  "insecure-registries": ["10.77.0.0/16"],
  "live-restore": true,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" },
  "features": { "buildkit": true }
}
JSON
  changed=1
elif ! grep -q '10.77.0.0/16' "$daemon"; then
  if command -v python3 >/dev/null 2>&1; then
    cp "$daemon" "$daemon.latrix-backup"
    python3 - "$daemon" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
regs = d.setdefault("insecure-registries", [])
if "10.77.0.0/16" not in regs:
    regs.append("10.77.0.0/16")
d.setdefault("live-restore", True)
d.setdefault("log-opts", {"max-size": "10m", "max-file": "3"})
json.dump(d, open(p, "w"), indent=2)
PY
    changed=1
    log "updated existing $daemon (backup in $daemon.latrix-backup)"
  else
    log "WARNING: $daemon exists; add \"insecure-registries\": [\"10.77.0.0/16\"] to it manually"
  fi
fi
systemctl enable docker >/dev/null 2>&1 || true
if [ "$changed" = 1 ] && systemctl is-active --quiet docker; then
  systemctl restart docker
else
  systemctl start docker
fi

modprobe wireguard 2>/dev/null || true
modprobe dummy 2>/dev/null || true

# Firewall: web traffic + the WireGuard mesh; trust the mesh and docker bridge.
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
  log "configuring ufw"
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
  ufw allow 51870/udp >/dev/null
  ufw allow in on latrix0 >/dev/null
  ufw allow in on docker0 >/dev/null
fi
if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
  log "configuring firewalld"
  firewall-cmd -q --permanent --add-service=http --add-service=https
  firewall-cmd -q --permanent --add-port=51870/udp
  firewall-cmd -q --permanent --zone=trusted --add-interface=latrix0 || true
  firewall-cmd -q --permanent --zone=trusted --add-interface=latrix-vip || true
  firewall-cmd -q --permanent --zone=trusted --add-interface=docker0 || true
  firewall-cmd -q --reload
fi

mkdir -p /var/lib/latrix
chmod 700 /var/lib/latrix

cat > /etc/systemd/system/latrix.service <<'UNIT'
[Unit]
Description=latrix agent
Documentation=https://github.com/jreoka/latrix
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
ExecStart=/usr/local/bin/latrix agent run
Restart=always
RestartSec=3
LimitNOFILE=1048576
Environment=RUST_LOG=info
# Containers are owned by Docker and keep running when the agent restarts.

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
log "machine setup complete"
