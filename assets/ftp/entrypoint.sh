#!/bin/sh
set -eu

mkdir -p /var/run/vsftpd/empty
chmod 755 /var/run/vsftpd/empty

CFG_DIR="/etc/vsftpd"
mkdir -p "$CFG_DIR/users.d"

resolve_ipv4() {
  v="$1"
  if echo "$v" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
    echo "$v"
    return 0
  fi

  if command -v getent >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "$v" 2>/dev/null | awk 'NR==1{print $1}')"
    if [ -n "${ip:-}" ]; then
      echo "$ip"
      return 0
    fi
  fi

  if command -v python3 >/dev/null 2>&1; then
    ip="$(python3 - <<PY 2>/dev/null || true
import socket
try:
    print(socket.gethostbyname("$v"))
except Exception:
    pass
PY
)"
    if [ -n "${ip:-}" ]; then
      echo "$ip"
      return 0
    fi
  fi

  echo "$v"
}

PASV_HOST="${FTP_PUBLIC_HOST:-127.0.0.1}"
PASV_ADDR="$(resolve_ipv4 "$PASV_HOST")"

echo "[FTP] Starting vsftpd with PASV address: $PASV_ADDR"

cat > "$CFG_DIR/vsftpd.conf" <<EOF
listen=YES
listen_ipv6=NO
background=NO

xferlog_enable=YES
log_ftp_protocol=YES
vsftpd_log_file=/var/log/vsftpd.log

anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=002
use_localtime=YES
seccomp_sandbox=NO

chroot_local_user=YES
allow_writeable_chroot=YES
secure_chroot_dir=/var/run/vsftpd/empty

pam_service_name=vsftpd_virtual
guest_enable=YES
guest_username=ftp
virtual_use_local_privs=YES
user_config_dir=${CFG_DIR}/users.d

local_root=/var/www

pasv_enable=YES
pasv_min_port=${FTP_PASV_MIN:-21000}
pasv_max_port=${FTP_PASV_MAX:-21010}
pasv_address=${PASV_ADDR}
pasv_addr_resolve=NO

ssl_enable=${FTP_TLS:-NO}
rsa_cert_file=/etc/ssl/private/vsftpd.pem
rsa_private_key_file=/etc/ssl/private/vsftpd.pem
force_local_logins_ssl=${FTP_TLS:-NO}
force_local_data_ssl=${FTP_TLS:-NO}
EOF

chown root:root "$CFG_DIR/vsftpd.conf"
chmod 600 "$CFG_DIR/vsftpd.conf"

cat > /etc/pam.d/vsftpd_virtual <<EOF
auth required pam_userdb.so db=${CFG_DIR}/users crypt=crypt
account required pam_userdb.so db=${CFG_DIR}/users crypt=crypt
session required pam_loginuid.so
EOF

chown root:root /etc/pam.d/vsftpd_virtual
chmod 644 /etc/pam.d/vsftpd_virtual

echo "[FTP] PAM config:"
cat /etc/pam.d/vsftpd_virtual

HOST_UID="${PUID:-${FTP_HOST_UID:-1000}}"
HOST_GID="${PGID:-${FTP_HOST_GID:-1000}}"

if getent group ftp >/dev/null 2>&1; then
  CUR_GID="$(getent group ftp | awk -F: '{print $3}')"
  if [ "$CUR_GID" != "$HOST_GID" ]; then
    groupmod -g "$HOST_GID" ftp 2>/dev/null || true
  fi
else
  groupadd -g "$HOST_GID" ftp 2>/dev/null || groupadd ftp 2>/dev/null || true
fi

if id ftp >/dev/null 2>&1; then
  CUR_UID="$(id -u ftp)"
  CUR_GID="$(id -g ftp)"
  if [ "$CUR_UID" != "$HOST_UID" ]; then
    usermod -u "$HOST_UID" ftp 2>/dev/null || true
  fi
  if [ "$CUR_GID" != "$HOST_GID" ]; then
    usermod -g "$HOST_GID" ftp 2>/dev/null || true
  fi
else
  useradd -m -u "$HOST_UID" -g "$HOST_GID" -d /var/www -s /usr/sbin/nologin ftp 2>/dev/null || true
fi

echo "[FTP] ftp user mapped to ${HOST_UID}:${HOST_GID}"

echo "[FTP] Waiting for users.db..."
for i in $(seq 1 30); do
  if [ -f "$CFG_DIR/users.db" ]; then
    echo "[FTP] users.db found"
    break
  fi
  if [ $i -eq 30 ]; then
    echo "[FTP] WARNING: users.db not found after 30s, creating empty DB"
    touch "$CFG_DIR/users.txt"
    if command -v db5.3_load >/dev/null 2>&1; then
      db5.3_load -T -t hash -f "$CFG_DIR/users.txt" "$CFG_DIR/users.db" || true
    else
      db_load -T -t hash -f "$CFG_DIR/users.txt" "$CFG_DIR/users.db" || true
    fi
  fi
  sleep 1
done

chown root:root "$CFG_DIR/users.db" 2>/dev/null || true
chmod 600 "$CFG_DIR/users.db" 2>/dev/null || true

if [ -d "$CFG_DIR/users.d" ]; then
  chown root:root "$CFG_DIR/users.d" || true
  chmod 755 "$CFG_DIR/users.d" || true
  find "$CFG_DIR/users.d" -maxdepth 1 -type f -exec chown root:root {} \; 2>/dev/null || true
  find "$CFG_DIR/users.d" -maxdepth 1 -type f -exec chmod 600 {} \; 2>/dev/null || true
fi

echo "[FTP] Config complete, starting vsftpd..."
echo "[FTP] users.db status:"
ls -la "$CFG_DIR/users.db" 2>/dev/null || echo "  (not found)"

exec /usr/sbin/vsftpd "$CFG_DIR/vsftpd.conf"
