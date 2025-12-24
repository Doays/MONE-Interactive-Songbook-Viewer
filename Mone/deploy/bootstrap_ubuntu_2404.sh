#!/usr/bin/env bash
set -euo pipefail

# ✅ 네 깃헙 레포
REPO_URL="https://github.com/Doays/MONE-Interactive-Songbook-Viewer.git"

# ✅ 설치 위치/데이터 위치
APP_DIR="/opt/mone-songbook"
DATA_DIR="/var/lib/mone-songbook"
ENV_FILE="/etc/mone-songbook.env"

sudo apt-get update -y
sudo apt-get install -y git nginx ca-certificates curl

# ✅ Ubuntu 24.04: Node 20 LTS (nodesource)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# ✅ 서비스 유저
if ! id -u moneapp >/dev/null 2>&1; then
  sudo useradd -r -m -s /usr/sbin/nologin moneapp
fi

# ✅ clone/pull
if [ ! -d "$APP_DIR/.git" ]; then
  sudo rm -rf "$APP_DIR"
  sudo git clone "$REPO_URL" "$APP_DIR"
else
  sudo git -C "$APP_DIR" pull
fi
sudo chown -R moneapp:moneapp "$APP_DIR"

# ✅ deps
sudo -u moneapp bash -lc "cd '$APP_DIR' && npm install --omit=dev"

# ✅ data dir
sudo mkdir -p "$DATA_DIR"
sudo chown -R moneapp:moneapp "$DATA_DIR"

# ✅ env 생성 (서버 만든 뒤 반드시 수정!)
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" >/dev/null <<EOF
PORT=8080
TRUST_PROXY=1
COOKIE_SECURE=0
DATA_DIR=$DATA_DIR

# ⚠️ 너의 Apps Script URL로 바꿔라
APPS_SCRIPT_URL=https://script.google.com/macros/s/XXXX/exec

REFRESH_INTERVAL_MS=60000
FETCH_TIMEOUT_MS=12000

# 필요하면 채워라
CHZZK_CHANNEL_ID=5c897b3e639045ca6e314bbaff991f73
NID_AUT=
NID_SES=
CHZZK_LIVE_POLL_MS=5000
CHZZK_HTTP_TIMEOUT_MS=15000
CHZZK_MISSION_LIMIT=50

# ⚠️ 반드시 바꿔라
MASTER_PASSWORD=CHANGE_ME_NOW
DEFAULT_PASSWORD=mone
SESSION_TTL_DAYS=30

# 필요할 때만 (비우면 동일 오리진만)
CORS_ORIGIN=
EOF
  sudo chmod 600 "$ENV_FILE"
fi

# ✅ nginx reverse proxy (80 -> 127.0.0.1:8080)
sudo tee /etc/nginx/sites-available/mone-songbook >/dev/null <<'EOF'
server {
  listen 80;
  server_name _;

  location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_http_version 1.1;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    proxy_read_timeout 60s;
  }
}
EOF

sudo ln -sf /etc/nginx/sites-available/mone-songbook /etc/nginx/sites-enabled/mone-songbook
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl enable --now nginx

# ✅ systemd service
sudo tee /etc/systemd/system/mone-songbook.service >/dev/null <<'EOF'
[Unit]
Description=MONE Interactive Songbook Viewer
After=network.target

[Service]
Type=simple
User=moneapp
Group=moneapp
WorkingDirectory=/opt/mone-songbook
EnvironmentFile=/etc/mone-songbook.env
ExecStart=/usr/bin/node /opt/mone-songbook/server.js
Restart=always
RestartSec=2
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now mone-songbook

echo "✅ DONE"
echo "🔎 status: sudo systemctl status mone-songbook --no-pager"
echo "🔎 logs  : sudo journalctl -u mone-songbook -f"
