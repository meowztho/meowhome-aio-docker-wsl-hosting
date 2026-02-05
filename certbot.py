import os
import sys
import subprocess
import shutil
import time
from pathlib import Path
import socket
import ctypes

# --------------------
# Konfiguration
# --------------------
CERTBOT_PATH = r"C:\Users\sebif\AppData\Local\Programs\Python\Python312\Scripts\certbot.exe"

DOMAINS = [
    "camping-freunde.eu", "www.camping-freunde.eu",
    "it-phi.de", "www.it-phi.de", 
    "phi-computers.de", "www.phi-computers.de"
]

EMAIL = "sebastian.farrnbacher@phi-computers.de"

# XAMPP Pfade
XAMPP_BASE = r"D:\Xampp"
APACHE_BIN = r"D:\Xampp\apache\bin\httpd.exe"
APACHE_CONF = r"D:\Xampp\apache\conf"
XAMPP_CERT_DST = r"D:\Xampp\apache\conf\ssl.crt\server.crt"
XAMPP_KEY_DST = r"D:\Xampp\apache\conf\ssl.key\server.key"

# --------------------
# Hilfsfunktionen
# --------------------
def is_admin():
    """Prüft ob das Script als Administrator ausgeführt wird"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_command(cmd, check=True):
    """Führt einen Befehl aus und gibt Output zurück"""
    print(f"🚀 Ausführen: {cmd}")
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if result.stdout:
        print(f"📋 Output: {result.stdout}")
    if result.stderr:
        print(f"⚠️  Error: {result.stderr}")
    
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(result.returncode, cmd, result.stdout, result.stderr)
    
    return result

def is_port_in_use(port):
    """Prüft ob ein Port belegt ist"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def stop_apache():
    """Stoppt Apache Webserver"""
    print("🛑 Stoppe Apache...")
    try:
        if not os.path.exists(APACHE_BIN):
            print(f"❌ Apache Binary nicht gefunden: {APACHE_BIN}")
            return False
            
        run_command(f'"{APACHE_BIN}" -k stop', check=False)
        time.sleep(5)
        
        if is_port_in_use(80) or is_port_in_use(443):
            print("Apache reagiert nicht, erzwinge Stop...")
            run_command('taskkill /F /IM httpd.exe', check=False)
            time.sleep(3)
            
        return True
    except Exception as e:
        print(f"⚠️  Warnung beim Apache Stop: {e}")
        return False

def start_apache():
    """Startet Apache Webserver"""
    print("🔄 Starte Apache...")
    try:
        run_command(f'"{APACHE_BIN}" -t')
        run_command(f'"{APACHE_BIN}" -k start')
        time.sleep(5)
        
        if is_port_in_use(80):
            print("✅ Apache erfolgreich gestartet")
            return True
        else:
            print("❌ Apache startet nicht - überprüfe Konfiguration")
            return False
            
    except subprocess.CalledProcessError as e:
        print(f"❌ Apache Konfigurationsfehler: {e}")
        return False

def wait_for_port_free(port, timeout=30):
    """Wartet bis Port frei ist"""
    print(f"⏳ Warte bis Port {port} frei ist...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        if not is_port_in_use(port):
            return True
        time.sleep(2)
    return False

def setup_xampp_ssl_directories():
    """Richtet die SSL-Verzeichnisse in XAMPP ein"""
    print("📁 Richte SSL-Verzeichnisse ein...")
    
    ssl_crt_dir = os.path.dirname(XAMPP_CERT_DST)
    ssl_key_dir = os.path.dirname(XAMPP_KEY_DST)
    
    os.makedirs(ssl_crt_dir, exist_ok=True)
    os.makedirs(ssl_key_dir, exist_ok=True)
    
    print(f"✅ SSL Zertifikat-Verzeichnis: {ssl_crt_dir}")
    print(f"✅ SSL Key-Verzeichnis: {ssl_key_dir}")
    
    return True

def configure_apache_vhosts():
    """Konfiguriert Apache Virtual Hosts für HTTPS"""
    print("🌐 Konfiguriere Apache Virtual Hosts...")
    
    vhost_config = f'''
# SSL Configuration for {DOMAINS[0]}
Listen 443
SSLCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLProxyCipherSuite HIGH:MEDIUM:!MD5:!RC4:!3DES
SSLHonorCipherOrder on 
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLProxyProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLPassPhraseDialog builtin
SSLSessionCache "shmcb:D:/Xampp/apache/logs/ssl_scache(512000)"
SSLSessionCacheTimeout 300

<VirtualHost *:443>
    ServerName {DOMAINS[0]}
    ServerAlias {" ".join(DOMAINS[1:])}
    DocumentRoot "D:/Xampp/htdocs"
    
    SSLEngine on
    SSLCertificateFile "D:/Xampp/apache/conf/ssl.crt/server.crt"
    SSLCertificateKeyFile "D:/Xampp/apache/conf/ssl.key/server.key"
    
    ErrorLog "D:/Xampp/apache/logs/ssl_error.log"
    TransferLog "D:/Xampp/apache/logs/ssl_access.log"
    
    <Directory "D:/Xampp/htdocs">
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>

<VirtualHost *:80>
    ServerName {DOMAINS[0]}
    ServerAlias {" ".join(DOMAINS[1:])}
    DocumentRoot "D:/Xampp/htdocs"
    
    # Redirect to HTTPS
    RewriteEngine On
    RewriteCond %{{HTTPS}} off
    RewriteRule ^(.*)$ https://%{{HTTP_HOST}}%{{REQUEST_URI}} [L,R=301]
</VirtualHost>
'''
    
    vhost_file = os.path.join(APACHE_CONF, "extra", "httpd-vhosts-ssl.conf")
    
    try:
        with open(vhost_file, 'w', encoding='utf-8') as f:
            f.write(vhost_config)
        print(f"✅ Virtual Host Konfiguration erstellt: {vhost_file}")
        return True
    except Exception as e:
        print(f"❌ Fehler beim Erstellen der Virtual Host Konfiguration: {e}")
        return False

def enable_apache_modules():
    """Aktiviert notwendige Apache Module"""
    print("⚙️ Aktiviere Apache Module...")
    
    httpd_conf = os.path.join(APACHE_CONF, "httpd.conf")
    
    if not os.path.exists(httpd_conf):
        print(f"❌ httpd.conf nicht gefunden: {httpd_conf}")
        return False
    
    try:
        with open(httpd_conf, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Module die aktiviert werden müssen
        modules_to_enable = [
            ('LoadModule ssl_module modules/mod_ssl.so', 'LoadModule ssl_module modules/mod_ssl.so'),
            ('LoadModule rewrite_module modules/mod_rewrite.so', 'LoadModule rewrite_module modules/mod_rewrite.so'),
            ('LoadModule socache_shmcb_module modules/mod_socache_shmcb.so', 'LoadModule socache_shmcb_module modules/mod_socache_shmcb.so'),
            ('#Include conf/extra/httpd-vhosts.conf', 'Include conf/extra/httpd-vhosts.conf'),
            ('#Include conf/extra/httpd-ssl.conf', 'Include conf/extra/httpd-vhosts-ssl.conf')
        ]
        
        modified = False
        for comment_line, active_line in modules_to_enable:
            if comment_line in content and active_line not in content:
                content = content.replace(comment_line, active_line)
                print(f"✅ Aktiviert: {active_line}")
                modified = True
            elif active_line in content:
                print(f"✅ Bereits aktiv: {active_line}")
            else:
                print(f"⚠️  Nicht gefunden: {active_line}")
        
        if modified:
            # Backup der originalen Konfiguration
            backup_file = httpd_conf + '.backup'
            shutil.copy2(httpd_conf, backup_file)
            print(f"📦 Backup erstellt: {backup_file}")
            
            # Neue Konfiguration schreiben
            with open(httpd_conf, 'w', encoding='utf-8') as f:
                f.write(content)
            print("✅ Apache Konfiguration aktualisiert")
        
        return True
        
    except Exception as e:
        print(f"❌ Fehler beim Konfigurieren von Apache: {e}")
        return False

def cleanup_old_certbot_configs():
    """Bereinigt alte Certbot Konfigurationen für einen Neustart"""
    print("🧹 Bereinige alte Certbot Konfigurationen...")
    
    certbot_paths = [
        Path(r"C:\Certbot"),
        Path(os.getenv('LOCALAPPDATA')) / 'letsencrypt',
        Path(os.getenv('APPDATA')) / 'letsencrypt',
    ]
    
    for path in certbot_paths:
        if path.exists():
            print(f"📁 Certbot Pfad gefunden: {path}")
            # Lösche nicht, sondern benenne um für Backup
            backup_path = path.parent / (path.name + "_backup")
            try:
                if backup_path.exists():
                    shutil.rmtree(backup_path)
                shutil.move(path, backup_path)
                print(f"✅ Backup erstellt: {backup_path}")
            except Exception as e:
                print(f"⚠️  Konnte {path} nicht backupen: {e}")

def get_first_time_certificate():
    """Holt ein komplett neues SSL Zertifikat"""
    print("🆕 Erstelle neues SSL Zertifikat...")
    
    domain_args = " ".join([f"-d {domain}" for domain in DOMAINS])
    
    cmd = (
        f'"{CERTBOT_PATH}" certonly --standalone '
        f'--non-interactive --agree-tos --email {EMAIL} '
        f'--preferred-challenges http --http-01-port 80 '
        f'{domain_args}'
    )
    
    try:
        result = run_command(cmd, check=False)
        
        if result.returncode == 0:
            print("✅ Neues Zertifikat erfolgreich erstellt")
            return True
        else:
            error_output = result.stderr.lower()
            
            if "too many certificates" in error_output:
                print("❌ RATE LIMIT FEHLER!")
                print("Da Sie ein komplett neues Setup haben, warten Sie bitte bis:")
                print("⏳ 2025-11-28 02:52:08 MEZ")
                print("Oder verwenden Sie vorübergehend ein selbstsigniertes Zertifikat.")
                return False
            else:
                print(f"❌ Certbot Fehler: {result.stderr}")
                return False
                
    except Exception as e:
        print(f"❌ Unerwarteter Fehler bei Certbot: {e}")
        return False

def find_and_copy_certificates():
    """Findet und kopiert die Certbot Zertifikate"""
    print("🔍 Suche Zertifikate...")
    
    possible_paths = [
        Path(r"C:\Certbot\live") / DOMAINS[0],
        Path(os.getenv('LOCALAPPDATA')) / 'letsencrypt' / 'live' / DOMAINS[0],
        Path(os.getenv('APPDATA')) / 'letsencrypt' / 'live' / DOMAINS[0],
    ]
    
    for live_path in possible_paths:
        cert_file = live_path / 'fullchain.pem'
        key_file = live_path / 'privkey.pem'
        
        if cert_file.exists() and key_file.exists():
            print(f"✅ Zertifikate gefunden in: {live_path}")
            
            # Kopiere Zertifikate
            try:
                shutil.copy2(cert_file, XAMPP_CERT_DST)
                shutil.copy2(key_file, XAMPP_KEY_DST)
                print(f"✅ Zertifikat kopiert: {XAMPP_CERT_DST}")
                print(f"✅ Key kopiert: {XAMPP_KEY_DST}")
                return True
            except Exception as e:
                print(f"❌ Fehler beim Kopieren: {e}")
                return False
    
    print("❌ Keine Zertifikate gefunden")
    return False

def create_self_signed_certificate():
    """Erstellt ein selbstsigniertes Zertifikat als Fallback"""
    print("🔧 Erstelle selbstsigniertes Zertifikat (Fallback)...")
    
    # Stelle sicher, dass OpenSSL verfügbar ist
    openssl_path = r"D:\Xampp\apache\bin\openssl.exe"
    if not os.path.exists(openssl_path):
        print("❌ OpenSSL nicht gefunden in XAMPP")
        return False
    
    # Konfiguration für selbstsigniertes Zertifikat
    ssl_config = f'''
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn

[dn]
C = DE
ST = Bavaria
L = Munich
O = PHI Computers
OU = IT
CN = {DOMAINS[0]}
emailAddress = {EMAIL}

[ext]
subjectAltName = @alt_names

[alt_names]
'''
    
    # Füge alle Domains als Subject Alternative Names hinzu
    for i, domain in enumerate(DOMAINS, 1):
        ssl_config += f'DNS.{i} = {domain}\n'
    
    config_file = os.path.join(APACHE_CONF, "ssl_config.cnf")
    
    try:
        # Schreibe Konfigurationsdatei
        with open(config_file, 'w') as f:
            f.write(ssl_config)
        
        # Erstelle privaten Key
        key_cmd = f'"{openssl_path}" genrsa -out "{XAMPP_KEY_DST}" 2048'
        run_command(key_cmd)
        
        # Erstelle Zertifikat
        cert_cmd = f'"{openssl_path}" req -new -x509 -key "{XAMPP_KEY_DST}" -out "{XAMPP_CERT_DST}" -days 365 -config "{config_file}" -extensions ext'
        run_command(cert_cmd)
        
        print("✅ Selbstsigniertes Zertifikat erstellt (gültig 365 Tage)")
        return True
        
    except Exception as e:
        print(f"❌ Fehler beim Erstellen des selbstsignierten Zertifikats: {e}")
        return False
    finally:
        # Lösche temporäre Konfigurationsdatei
        if os.path.exists(config_file):
            os.remove(config_file)

def check_certbot_availability():
    """Prüft ob Certbot verfügbar ist"""
    print("🔍 Prüfe Certbot...")
    if not os.path.exists(CERTBOT_PATH):
        print(f"❌ Certbot nicht gefunden unter: {CERTBOT_PATH}")
        print("📥 Installiere mit: pip install certbot")
        return False
    
    try:
        result = run_command(f'"{CERTBOT_PATH}" --version', check=False)
        if result.returncode == 0:
            print(f"✅ Certbot gefunden: {result.stdout.strip()}")
            return True
        else:
            print("❌ Certbot kann nicht ausgeführt werden")
            return False
    except Exception as e:
        print(f"❌ Certbot Check fehlgeschlagen: {e}")
        return False

def verify_xampp_installation():
    """Überprüft die XAMPP Installation"""
    print("🔍 Überprüfe XAMPP Installation...")
    
    required_paths = [
        XAMPP_BASE,
        APACHE_BIN,
        APACHE_CONF,
        os.path.join(APACHE_CONF, "extra")
    ]
    
    for path in required_paths:
        if not os.path.exists(path):
            print(f"❌ Pfad nicht gefunden: {path}")
            return False
    
    print("✅ XAMPP Installation verifiziert")
    return True

# --------------------
# Hauptprogramm
# --------------------
def main():
    print("=" * 70)
    print("🆕 KOMPLETTE SSL EINRICHTUNG FÜR NEUE XAMPP INSTALLATION")
    print("=" * 70)
    print(f"🌐 Domains: {', '.join(DOMAINS)}")
    print(f"📧 E-Mail: {EMAIL}")
    print(f"📍 XAMPP Pfad: {XAMPP_BASE}")
    print()
    
    if not is_admin():
        print("❌ Bitte als Administrator ausführen!")
        input("Drücke Enter zum Beenden...")
        sys.exit(1)
    
    print("✅ Administrator-Rechte bestätigt")
    
    # 1. XAMPP Installation prüfen
    if not verify_xampp_installation():
        print("❌ XAMPP Installation nicht korrekt")
        sys.exit(1)
    
    # 2. Certbot prüfen
    if not check_certbot_availability():
        print("❌ Certbot nicht verfügbar")
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("1. VORBEREITUNG")
    print("=" * 70)
    
    # 3. Alte Konfigurationen bereinigen
    cleanup_old_certbot_configs()
    
    # 4. SSL-Verzeichnisse einrichten
    if not setup_xampp_ssl_directories():
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("2. APACHE KONFIGURATION")
    print("=" * 70)
    
    # 5. Apache Module aktivieren
    if not enable_apache_modules():
        print("⚠️  Apache Konfiguration könnte Probleme haben")
    
    # 6. Virtual Hosts konfigurieren
    if not configure_apache_vhosts():
        print("⚠️  Virtual Host Konfiguration könnte Probleme haben")
    
    print("\n" + "=" * 70)
    print("3. SSL ZERTIFIKAT")
    print("=" * 70)
    
    # 7. Apache stoppen für Certbot
    if not stop_apache():
        print("❌ Apache konnte nicht gestoppt werden")
        sys.exit(1)
    
    if not wait_for_port_free(80):
        print("❌ Port 80 ist noch belegt!")
        sys.exit(1)
    
    print("✅ Port 80 ist frei")
    
    # 8. Neues Zertifikat holen
    if not get_first_time_certificate():
        print("❌ Konnte kein Let's Encrypt Zertifikat erhalten")
        
        # Fallback: Selbstsigniertes Zertifikat
        print("\n🔄 Versuche Fallback: Selbstsigniertes Zertifikat...")
        if create_self_signed_certificate():
            print("✅ Selbstsigniertes Zertifikat als Fallback erstellt")
        else:
            print("❌ Auch Fallback fehlgeschlagen")
            print("🔄 Starte Apache ohne SSL...")
            start_apache()
            sys.exit(1)
    else:
        # 9. Zertifikate kopieren
        if not find_and_copy_certificates():
            print("❌ Konnte Zertifikate nicht kopieren")
            sys.exit(1)
    
    print("\n" + "=" * 70)
    print("4. FINALE EINRICHTUNG")
    print("=" * 70)
    
    # 10. Apache starten
    if not start_apache():
        print("❌ Apache konnte nicht gestartet werden")
        sys.exit(1)
    
    # 11. Zusammenfassung
    print("\n" + "=" * 70)
    print("✅ ERFOLGREICH EINGERICHTET!")
    print("=" * 70)
    
    print(f"📋 ZUSAMMENFASSUNG:")
    print(f"   🌐 Domains: {', '.join(DOMAINS)}")
    print(f"   📍 XAMPP Pfad: {XAMPP_BASE}")
    print(f"   🔐 Zertifikat: {XAMPP_CERT_DST}")
    print(f"   🔑 Private Key: {XAMPP_KEY_DST}")
    print(f"   🌍 HTTP → HTTPS Redirect: Aktiviert")
    print(f"   ⚠️  Port 80 & 443: Überwache in Firewall")
    
    print(f"\n📋 MANUELLE SCHRITTE IN XAMPP:")
    print(f"   1. Öffne: {APACHE_CONF}\\httpd.conf")
    print(f"   2. Suche und aktiviere (entferne '#'):")
    print(f"      - LoadModule ssl_module modules/mod_ssl.so")
    print(f"      - LoadModule rewrite_module modules/mod_rewrite.so")
    print(f"      - Include conf/extra/httpd-vhosts-ssl.conf")
    print(f"   3. Starte Apache neu falls nötig")
    
    print(f"\n🔍 TESTEN:")
    print(f"   - Besuche https://{DOMAINS[0]}")
    print(f"   - Prüfe ob SSL-Symbol im Browser erscheint")
    print(f"   - Teste Redirect von HTTP zu HTTPS")
    
    print(f"\n⚠️  HINWEISE:")
    print(f"   - Firewall: Stelle sicher dass Port 80 & 443 offen sind")
    print(f"   - Router: Portweiterleitung falls nötig")
    print(f"   - DynDNS: Falls keine statische IP vorhanden")

if __name__ == "__main__":
    main()