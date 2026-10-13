#!/usr/bin/env bash
# CloudBox installer for Ubuntu (also works on Raspberry Pi OS / Ubuntu on Pi, 64-bit)
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Please run with sudo:  sudo ./install.sh"; exit 1
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MNT=/srv/cloudbox/mnt

echo "==> Checking Docker"
if ! command -v docker >/dev/null 2>&1; then
  echo "Docker not found. Installing from get.docker.com..."
  curl -fsSL https://get.docker.com | sh
fi
docker compose version >/dev/null 2>&1 || { echo "Docker Compose plugin missing: sudo apt install docker-compose-plugin"; exit 1; }

echo "==> Preparing shared mount directory $MNT"
mkdir -p "$MNT"
# Make it its own mount point with shared propagation so mounts made inside the container appear on the host
if ! findmnt -no TARGET "$MNT" >/dev/null 2>&1; then
  mount --bind "$MNT" "$MNT"
fi
mount --make-rshared "$MNT"

cat > /etc/systemd/system/cloudbox-mounts.service <<EOF
[Unit]
Description=CloudBox shared mount point
Before=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'mkdir -p $MNT; findmnt $MNT >/dev/null || mount --bind $MNT $MNT; mount --make-rshared $MNT'

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable cloudbox-mounts.service >/dev/null

ENV_FILE="$HERE/.env"
if [[ -f "$ENV_FILE" ]]; then
  echo "==> Using existing $ENV_FILE"
else
  echo "==> Configuration"
  read -rsp "Choose a CloudBox password: " PW; echo
  [[ -n "$PW" ]] || { echo "Password cannot be empty."; exit 1; }
  read -rp "ngrok authtoken (https://dashboard.ngrok.com/get-started/your-authtoken): " NG
  [[ -n "$NG" ]] || { echo "ngrok authtoken is required."; exit 1; }
  ROOT_SRC="$(findmnt -no SOURCE /)"
  ROOT_DISK="$(lsblk -no pkname "$ROOT_SRC" 2>/dev/null | head -n1 || true)"
  [[ -n "$ROOT_DISK" ]] || ROOT_DISK="$(basename "$ROOT_SRC")"
  umask 077
  cat > "$ENV_FILE" <<EOF
CLOUDBOX_PASSWORD=$PW
CLOUDBOX_SECRET=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
NGROK_AUTHTOKEN=$NG
ROOT_DISK=$ROOT_DISK
EOF
  echo "System disk detected as '$ROOT_DISK' (it will never be offered for sharing)."
fi

echo "==> Installing the 'cloudbox' command"
chmod +x "$HERE/cloudbox"
ln -sf "$HERE/cloudbox" /usr/local/bin/cloudbox

echo "==> Building and starting containers"
cd "$HERE"
docker compose up -d --build

# The app stores a hashed copy of the password on first start; then the plain-text one can leave .env
echo "==> Securing your password"
for _ in $(seq 1 30); do
  if docker compose exec -T app test -f /data/auth.json 2>/dev/null; then
    sed -i '/^CLOUDBOX_PASSWORD=/d' "$ENV_FILE"
    echo "Password is now stored hashed (removed from .env)."
    break
  fi
  sleep 1
done

echo
echo "CloudBox is running."
echo "  Admin dashboard : http://localhost:8000/admin   (sign in with your password)"
echo "  Client link     : shown in the admin dashboard under Client sharing (or run: cloudbox url)"
echo
echo "Turn it on/off any time:"
echo "  cloudbox stop     # OFF (also unmounts shared drives so you can unplug them safely)"
echo "  cloudbox start    # ON"
echo "  cloudbox status   # is it running, and what is shared"
echo "  cloudbox autostart off   # don't start at boot (default: starts at boot)"
echo "  cloudbox reset-password  # forgot your password? set a new one"
