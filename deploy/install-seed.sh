#!/usr/bin/env bash
# Instala un nodo semilla ARMax en un VPS Ubuntu/Debian. Ejecutar como root desde la raíz del repo:
#   sudo bash deploy/install-seed.sh
set -euo pipefail
command -v cargo >/dev/null || { echo "Instala Rust primero: curl https://sh.rustup.rs -sSf | sh"; exit 1; }
# con poca RAM (1 GB) compilar necesita swap
if [ "$(free -m | awk '/Mem:/{print $2}')" -lt 1800 ] && [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
fi
cargo build --release -p armax-node -j 1
id armax >/dev/null 2>&1 || useradd --system --home /var/lib/armax --shell /usr/sbin/nologin armax
install -d /opt/armax && install -m 755 target/release/armax-node /opt/armax/armax-node
install -m 644 deploy/armax-seed.service /etc/systemd/system/armax-seed.service
systemctl daemon-reload && systemctl enable --now armax-seed
command -v ufw >/dev/null && ufw allow 8333/tcp || true
sleep 5
echo "---- clave pública del nodo (cópiala) ----"
journalctl -u armax-seed -n 40 --no-pager | grep -i -E "clave|key|escuch|listen" || journalctl -u armax-seed -n 20 --no-pager
