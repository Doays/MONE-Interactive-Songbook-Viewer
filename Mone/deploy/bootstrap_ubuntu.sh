#!/usr/bin/env bash
set -euo pipefail

REPO_URL="https://github.com/Doays/MONE-Interactive-Songbook-Viewer.git"
APP_DIR="/opt/mone-songbook"
DATA_DIR="/var/lib/mone-songbook"
ENV_FILE="/etc/mone-songbook.env"

sudo apt-get update -y
sudo apt-get install -y git nginx ca-certificates curl

# Node.js 20 LTS
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

# app user
if ! id -u moneapp >/dev/null 2>&1; then
  sudo useradd -r -m -s /usr/sbin/nologin moneapp
fi

# clone
if [ ! -d "$APP_DIR" ]; then
  sudo git clone "$REPO_URL" "$APP_DIR"
else
  sudo git -C "$APP_DIR" pull
fi

sudo chown -R moneapp:moneapp "$APP_DIR"

# install deps
cd "$APP_DIR"
sudo -u moneapp npm install --omit=dev

# data dir
sudo mkdir -p "$DATA_DIR"
sudo chown -R moneapp:moneapp "$DATA_DIR"

# env (너가 서버 생성 후 꼭 수정해라)
if [ ! -f "$ENV_FILE" ]; then
  sudo tee "$ENV_FILE" >/dev/null <<EOF
PORT=8080
TRUST_PROXY=1
COOKIE_SECURE=0
DATA_DIR=$DATA_DIR

# 너의 Apps Script URL로 바꿔라
APPS_SCRIPT_URL=$APPS_SCRIPT_URL

REFRESH_INTERVAL_MS=60000
FETCH_TIMEOUT_MS=12000

# 필요하면 채워라
CHZZK_CHANNEL_ID=5c897b3e639045ca6e314bbaff991f73
NID_AUT=
NID_SES=

MASTER_PASSWORD=CHANGE_ME_NOW
DEFAULT_PASSWORD=mone
SESSION_TTL_DAYS=30
EOF
  sudo chmod 600 "$ENV_FILE"
fi

# nginx
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
sudo systemctl restart nginx
sudo systemctl enable nginx

# systemd service
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
sudo systemctl enable mone-songbook
sudo systemctl restart mone-songbook

echo "DONE. Check: systemctl status mone-songbook --no-pager"
