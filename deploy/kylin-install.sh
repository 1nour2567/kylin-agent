#!/bin/bash
set -euo pipefail

echo "=== Kylin Agent secure deployment ==="

INSTALL_DIR="${INSTALL_DIR:-/opt/kylin-agent}"
SERVICE_USER="${SERVICE_USER:-kylin-agent}"
SERVICE_NAME="${SERVICE_NAME:-kylin-agent}"
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-8008}"

if [ "${EUID}" -ne 0 ]; then
    echo "Please run as root for installation only. The service itself will run as ${SERVICE_USER}."
    exit 1
fi

echo "[1/7] Checking environment..."
echo "  Architecture: $(uname -m)"
echo "  OS: $(cat /etc/os-release 2>/dev/null | head -1 || echo 'unknown')"
python3 --version >/dev/null
echo "  Python: $(python3 --version 2>&1)"

# Verify auto-tier tools are available (#21)
echo "  Checking auto-tier tools..."
for cmd in ps systemctl journalctl ss df free lsof rpm; do
    if command -v $cmd >/dev/null 2>&1; then
        echo "    ✓ $cmd"
    else
        echo "    ⚠ $cmd not found — some tools may fail"
    fi
done

echo "[2/7] Creating restricted service user..."
if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
    useradd -r -m -d "/var/lib/${SERVICE_USER}" -s /usr/sbin/nologin "${SERVICE_USER}"
fi

echo "[3/7] Installing Python dependencies..."
cd "${INSTALL_DIR}"
python3 -m pip install -r requirements.txt

echo "[4/7] Writing .env template if missing..."
if [ ! -f .env ]; then
    umask 027
    cat > .env << ENVEOF
# Fill this in manually or inject it from a secret manager.
DEEPSEEK_API_KEY=
DEEPSEEK_BASE_URL=https://api.deepseek.com
DEEPSEEK_MODEL=deepseek-chat

HOST=${HOST}
PORT=${PORT}
CORS_ORIGINS=http://127.0.0.1:${PORT},http://localhost:${PORT}
ENVIRONMENT=production
AGENT_MODE=live

# Set true only when TLS is terminated by this app or a trusted reverse proxy.
ENFORCE_HTTPS=false
TLS_CERTFILE=
TLS_KEYFILE=

# Keep anonymous read disabled in production.
ALLOW_ANONYMOUS_READ=false

# Keep disabled unless /etc/sudoers.d/${SERVICE_NAME} grants only the exact
# commands needed for your demo or production runbook.
ALLOW_PRIVILEGED_CONFIRM=false
AGENT_RESTRICTED_USER=${SERVICE_USER}
ENVEOF
    chown root:"${SERVICE_USER}" .env
    chmod 0640 .env
else
    echo "    .env already exists; leaving it unchanged"
fi

echo "[5/7] Preparing writable directories..."
mkdir -p data/audit data/logs data/baseline /tmp/kylin-agent
chown -R "${SERVICE_USER}:${SERVICE_USER}" data /tmp/kylin-agent
chmod 0750 data /tmp/kylin-agent

echo "[6/7] Installing systemd service..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << SERVICEEOF
[Unit]
Description=Kylin Security Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=/usr/bin/python3 ${INSTALL_DIR}/backend/main.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${INSTALL_DIR}/data /tmp/kylin-agent
CapabilityBoundingSet=
LockPersonality=true

[Install]
WantedBy=multi-user.target
SERVICEEOF

systemctl daemon-reload

echo "[7/7] Done."
echo "Start with: systemctl enable --now ${SERVICE_NAME}"
echo "Local URL:  http://${HOST}:${PORT}"
echo
echo "Optional least-privilege sudo:"
echo "  If you enable ALLOW_PRIVILEGED_CONFIRM=true, create a sudoers rule that"
echo "  permits ${SERVICE_USER} only the exact systemctl/journalctl/kill/truncate"
echo "  commands required by your operational runbook. Do not grant broad NOPASSWD."
