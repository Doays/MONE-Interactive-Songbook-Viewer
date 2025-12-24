#!/usr/bin/env bash
set -euo pipefail
APP_DIR="/opt/mone-songbook"

sudo git -C "$APP_DIR" pull
sudo -u moneapp bash -lc "cd $APP_DIR && npm install --omit=dev"
sudo systemctl restart mone-songbook
sudo systemctl status mone-songbook --no-pager
