#!/usr/bin/env bash
# Repro Room: one-shot setup for a fresh Ubuntu 24.04 Vultr Cloud Compute VM.
#
#   git clone <this repo> && cd repro-room
#   sudo ./deploy/setup-vm.sh            # Docker (runc)
#   sudo ./deploy/setup-vm.sh --gvisor   # Docker + gVisor (runsc) as the sandbox runtime
#
# Installs Docker, optional gVisor, Caddy (automatic HTTPS on <public-ip>.sslip.io) and uv;
# creates the `reproroom` service user; installs the app to /opt/repro-room; writes
# /etc/repro-room/repro-room.env from the template (fill in LLM_API_KEY, then start the service).
set -euo pipefail

GVISOR=0
[[ "${1:-}" == "--gvisor" ]] && GVISOR=1
[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR=/opt/repro-room
APP_USER=reproroom
DATA_DIR=/var/lib/repro-room
ENV_DIR=/etc/repro-room
ENV_FILE=$ENV_DIR/repro-room.env
IMAGE=docker.io/library/python:3.12-slim

log() { printf '\n==> %s\n' "$*"; }

log "Base packages and Docker"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q ca-certificates curl gnupg rsync ufw docker.io python3.12 python3.12-venv \
  debian-keyring debian-archive-keyring apt-transport-https
systemctl enable --now docker

if [[ $GVISOR -eq 1 ]]; then
  log "gVisor (runsc)"
  curl -fsSL https://gvisor.dev/archive.key | gpg --dearmor --yes -o /usr/share/keyrings/gvisor-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" \
    > /etc/apt/sources.list.d/gvisor.list
  apt-get update -q
  apt-get install -y -q runsc
  runsc install          # registers the "runsc" runtime in /etc/docker/daemon.json
  systemctl restart docker
fi

log "Caddy"
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/gpg.key | gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt > /etc/apt/sources.list.d/caddy-stable.list
apt-get update -q
apt-get install -y -q caddy

log "uv"
if ! command -v uv >/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
fi

log "Service user and data directory"
id -u "$APP_USER" >/dev/null 2>&1 || useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_USER"
# The control plane talks to dockerd. Docker group membership is root-equivalent on the host,
# which is why untrusted code never runs in this process: only inside the sandbox containers.
usermod -aG docker "$APP_USER"
install -d -o "$APP_USER" -g "$APP_USER" -m 0711 "$DATA_DIR" "$DATA_DIR/work"

log "Application -> $APP_DIR"
install -d -m 0755 "$APP_DIR"
rsync -a --delete --exclude .venv --exclude data --exclude .git --exclude __pycache__ "$SRC_DIR/" "$APP_DIR/"
cd "$APP_DIR"
UV_PYTHON_DOWNLOADS=never uv sync --frozen --no-dev --python python3.12
chown -R root:root "$APP_DIR"

log "Sandbox image"
docker pull -q "$IMAGE"

log "Environment file"
install -d -m 0750 -g "$APP_USER" "$ENV_DIR"
if [[ ! -f $ENV_FILE ]]; then
  install -m 0640 -g "$APP_USER" "$APP_DIR/deploy/repro-room.env.example" "$ENV_FILE"
fi
set_env() {  # set_env KEY VALUE: replace or append KEY=VALUE in the env file
  if grep -q "^$1=" "$ENV_FILE"; then sed -i "s|^$1=.*|$1=$2|" "$ENV_FILE"; else echo "$1=$2" >> "$ENV_FILE"; fi
}
if [[ $GVISOR -eq 1 ]]; then set_env SANDBOX_OCI_RUNTIME runsc; fi
RUNTIME_ARGS=()
[[ $GVISOR -eq 1 ]] && RUNTIME_ARGS=(--runtime runsc)
if docker run --rm "${RUNTIME_ARGS[@]}" --init --network none "$IMAGE" true >/dev/null 2>&1; then
  set_env SANDBOX_INIT 1
else
  echo "docker --init unavailable here; sandboxes will run without an init process" >&2
  set_env SANDBOX_INIT 0
fi

log "Sandbox smoke test (limits in effect)"
docker run --rm "${RUNTIME_ARGS[@]}" --network none --read-only --user 65534:65534 --cap-drop ALL \
  --security-opt no-new-privileges --memory 512m --memory-swap 512m --pids-limit 128 "$IMAGE" \
  python -c "import os; print('sandbox ok, uid', os.getuid())"

log "systemd unit"
install -m 0644 "$APP_DIR/deploy/repro-room.service" /etc/systemd/system/repro-room.service
systemctl daemon-reload
systemctl enable repro-room

log "Caddy site on <public-ip>.sslip.io"
PUBLIC_IP="$(curl -fsS --max-time 3 http://169.254.169.254/v1/interfaces/0/ipv4/address 2>/dev/null || true)"
[[ -n $PUBLIC_IP ]] || PUBLIC_IP="$(curl -fsS --max-time 5 https://api.ipify.org)"
SITE="${PUBLIC_IP}.sslip.io"
sed "s|__SITE__|$SITE|" "$APP_DIR/deploy/Caddyfile.template" > /etc/caddy/Caddyfile
systemctl reload caddy || systemctl restart caddy

log "Firewall"
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

log "Block sandbox containers from the cloud metadata service and private ranges"
# The fetch phase has network (pip only), but no container should ever reach the VM's metadata
# endpoint or the host's private networks. DOCKER-USER is evaluated before Docker's own rules.
apt-get install -y -q iptables-persistent >/dev/null 2>&1 || true
for net in 169.254.0.0/16 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
  iptables -C DOCKER-USER -d "$net" -j DROP 2>/dev/null || iptables -I DOCKER-USER -d "$net" -j DROP
done
# Allow replies to established connections (e.g. DNS via Docker's embedded resolver on the bridge).
iptables -C DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
  || iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
netfilter-persistent save >/dev/null 2>&1 || true

cat <<EOF

Done. Next:
  1. Put the Vultr Serverless Inference key in $ENV_FILE (LLM_API_KEY=...).
  2. systemctl start repro-room && journalctl -u repro-room -f
  3. Open https://$SITE and run the containment drill.
EOF
