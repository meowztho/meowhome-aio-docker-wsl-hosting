#!/usr/bin/env bash
set -euo pipefail

echo "======================================"
echo "MeowFTP Debug Report"
echo "======================================"
echo ""

echo "1️⃣  Container Status:"
echo "--------------------------------------"
if docker ps --format '{{.Names}}' | grep -q meowhome_ftp; then
  echo "✓ Container laeuft"
  docker ps --filter name=meowhome_ftp --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
else
  echo "❌ Container laeuft NICHT"
fi
echo ""

echo "2️⃣  FTP Logs (letzte 30 Zeilen):"
echo "--------------------------------------"
docker logs --tail 30 meowhome_ftp 2>&1 || echo "Keine Logs verfuegbar"
echo ""

echo "3️⃣  vsftpd.conf:"
echo "--------------------------------------"
docker exec meowhome_ftp cat /etc/vsftpd/vsftpd.conf 2>/dev/null | head -30 || echo "❌ Nicht lesbar"
echo ""

echo "4️⃣  PAM Config:"
echo "--------------------------------------"
docker exec meowhome_ftp cat /etc/pam.d/vsftpd_virtual 2>/dev/null || echo "❌ Nicht lesbar"
echo ""

echo "5️⃣  Database Files:"
echo "--------------------------------------"
docker exec meowhome_ftp ls -la /etc/vsftpd/ 2>/dev/null | grep -E "users|\.db|\.txt" || echo "❌ Nicht verfuegbar"
echo ""

echo "6️⃣  User Database Content:"
echo "--------------------------------------"
docker exec meowhome_ftp sh -c "db5.3_dump /etc/vsftpd/users.db 2>/dev/null || db_dump /etc/vsftpd/users.db 2>/dev/null" | head -20 || echo "❌ Kann DB nicht lesen"
echo ""

echo "7️⃣  User Configs:"
echo "--------------------------------------"
docker exec meowhome_ftp ls -la /etc/vsftpd/users.d/ 2>/dev/null || echo "❌ Nicht verfuegbar"
echo ""

echo "8️⃣  Port Bindings:"
echo "--------------------------------------"
netstat -tlnp 2>/dev/null | grep -E ":21 |:2100" || ss -tlnp 2>/dev/null | grep -E ":21 |:2100" || echo "⚠️  netstat/ss nicht verfuegbar"
echo ""

if command -v curl >/dev/null 2>&1; then
  echo "9️⃣  FTP Connection Test:"
  echo "--------------------------------------"
  timeout 5 curl -v ftp://localhost:21 2>&1 | grep -E "220|Connected" || echo "⚠️  Keine Antwort"
  echo ""
fi

echo "🔟 /var/www Permissions:"
echo "--------------------------------------"
docker exec meowhome_ftp ls -la /var/www 2>/dev/null | head -10 || echo "❌ Nicht verfuegbar"
echo ""

echo "======================================"
echo "Tipps:"
echo "  - Login Test: ftp -p <your-ip> 21"
echo "  - Live Logs:  docker logs -f meowhome_ftp"
echo "  - Shell:      docker exec -it meowhome_ftp sh"
echo "======================================"
