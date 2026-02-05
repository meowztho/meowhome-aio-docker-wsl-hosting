# dns_updater.py
import os
import re
import json
import time
import logging
import tempfile
from json import JSONDecodeError
from datetime import datetime, timedelta, date
from typing import Optional, Tuple, Dict, Any, List

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from dotenv import load_dotenv

# ======================================================
# .env laden
# ======================================================
load_dotenv()

# Pflicht
CLOUDFLARE_API_TOKEN = os.getenv("CLOUDFLARE_API_TOKEN")
if not CLOUDFLARE_API_TOKEN:
    raise RuntimeError("CLOUDFLARE_API_TOKEN fehlt in .env")

# Defaults (konfigurierbar)
CLOUDFLARE_API_URL     = os.getenv("CLOUDFLARE_API_URL", "https://api.cloudflare.com/client/v4")
DOMAINS_RAW            = os.getenv("DOMAINS", "")
PROXIED_DEFAULT        = os.getenv("PROXIED_DEFAULT", "false").strip().lower() == "true"
PROXIED_OVERRIDES_RAW  = os.getenv("PROXIED_OVERRIDES", "")
FORCE_UPDATE_HOUR      = int(os.getenv("FORCE_UPDATE_HOUR", "6"))  # 0..23
CHECK_INTERVAL_SECONDS = int(os.getenv("CHECK_INTERVAL_SECONDS", "600"))
RETRY_INTERVAL_SECONDS = int(os.getenv("RETRY_INTERVAL_SECONDS", "300"))

APP_NAME = "DnsUpdater"

# ======================================================
# Pfad-Helfer
# ======================================================
def _default_state_dir() -> str:
    progdata = os.getenv("PROGRAMDATA")
    if progdata:
        return os.path.join(progdata, APP_NAME)
    local = os.getenv("LOCALAPPDATA")
    if local:
        return os.path.join(local, APP_NAME)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, APP_NAME)

def _expand(p: str) -> str:
    # %VAR% und ~ expandieren, dann normalisieren
    return os.path.normpath(os.path.expanduser(os.path.expandvars(p)))

def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)

def _norm_path(path_value: Optional[str], default_filename: str, default_dir: str) -> str:
    """
    Normalisiert einen Pfad:
    - expandiert %VAR% und ~
    - wenn kein Verzeichnisanteil vorhanden ist, nutze default_dir
    - wenn nur ein Verzeichnis angegeben wurde, hänge default_filename an
    """
    if not path_value:
        return os.path.join(default_dir, default_filename)
    p = _expand(path_value)
    d = os.path.dirname(p)
    f = os.path.basename(p)
    if not d:  # kein Ordner angegeben -> nutze default_dir
        return os.path.join(default_dir, f if f else default_filename)
    if not f:  # nur Ordner angegeben -> füge default_filename an
        return os.path.join(p, default_filename)
    return p

# Basispfade aus .env (können leer sein), dann normalisieren
STATE_DIR_ENV = os.getenv("STATE_DIR", "")
STATE_DIR = _expand(STATE_DIR_ENV) if STATE_DIR_ENV else _default_state_dir()
STATE_PATH = _norm_path(os.getenv("STATE_PATH"), "state.json", STATE_DIR)
LOG_PATH   = _norm_path(os.getenv("LOG_PATH"),   "dns_updater.log", STATE_DIR)

# Ordner anlegen
_ensure_dir(STATE_DIR)

# ======================================================
# Logging: Konsole + Datei
# ======================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
try:
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logging.getLogger().addHandler(file_handler)
except Exception as e:
    # Falls Log-Datei nicht schreibbar ist, weiter nur Konsole nutzen
    logging.warning(f"Kann Log-Datei nicht öffnen ({LOG_PATH}): {e}")

# ======================================================
# Helpers für .env-Parsing
# ======================================================
def slug_domain(d: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "_", d.strip().lower())

def parse_csv(val: str) -> List[str]:
    if not val:
        return []
    return [x.strip() for x in val.split(",") if x.strip()]

def parse_bool(val: Optional[str], default: bool=False) -> bool:
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "y", "on")

def load_domains_from_env() -> List[Dict[str, Any]]:
    """
    DOMAINS="zone1.com,zone2.de"
    Für jede Zone:
      - A_RECORDS_<slug>   = "zone1.com,sub1.zone1.com"
      - SPF_UPDATE_<slug>  = "true|false"
    """
    zones = parse_csv(DOMAINS_RAW)
    result: List[Dict[str, Any]] = []
    for z in zones:
        slug = slug_domain(z)
        a_records = parse_csv(os.getenv(f"A_RECORDS_{slug}", z))  # Default: Root-A-Record = Zone
        spf_update = parse_bool(os.getenv(f"SPF_UPDATE_{slug}", "true"))
        result.append({"zone": z, "a_records": a_records, "spf_update": spf_update})
    return result

def load_proxied_overrides() -> Dict[str, bool]:
    """
    PROXIED_OVERRIDES="mail.it-phi.de=false,api.example.com=true"
    """
    out: Dict[str, bool] = {}
    raw = PROXIED_OVERRIDES_RAW
    if not raw:
        return out
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair:
            continue
        if "=" not in pair:
            logging.warning(f"PROXIED_OVERRIDES-Eintrag ohne '=' ignoriert: {pair}")
            continue
        host, val = pair.split("=", 1)
        out[host.strip().lower()] = parse_bool(val, default=False)
    return out

DOMAINS = load_domains_from_env()
PROXIED_OVERRIDES = load_proxied_overrides()

if not DOMAINS:
    raise RuntimeError("DOMAINS ist leer. Bitte in .env setzen, z. B. DOMAINS=\"example.com\"")

# ======================================================
# HTTP Session mit Retries
# ======================================================
HEADERS = {"Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}", "Content-Type": "application/json"}

def build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=5,
        connect=5,
        read=5,
        backoff_factor=1.5,
        status_forcelist=(429, 500, 502, 503, 504),
        allowed_methods=frozenset(["GET", "PUT", "POST", "DELETE"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update(HEADERS)
    return s

SESSION = build_session()

# ======================================================
# State laden/speichern robust + atomar
# ======================================================
def load_state() -> Dict[str, Any]:
    try:
        if not os.path.exists(STATE_PATH):
            return {"last_known_ip": None, "last_force_date": None}
        with open(STATE_PATH, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except JSONDecodeError:
                logging.warning(f"Defekte State-Datei erkannt, neu initialisieren: {STATE_PATH}")
                return {"last_known_ip": None, "last_force_date": None}
    except Exception as e:
        logging.error(f"State laden fehlgeschlagen ({STATE_PATH}): {e}")
        return {"last_known_ip": None, "last_force_date": None}

def _safe_tmp(dirpath: str) -> str:
    # Windows: Tempfile im Zielordner erstellen (wichtig für atomaren replace)
    return tempfile.NamedTemporaryFile("w", dir=dirpath, delete=False, encoding="utf-8").name

def save_state(state: Dict[str, Any]) -> None:
    # Zielordner aus STATE_PATH ermitteln; wenn leer, nutze STATE_DIR
    dir_for_state = os.path.dirname(STATE_PATH) or STATE_DIR
    _ensure_dir(dir_for_state)

    attempts = 5
    last_err: Optional[Exception] = None
    for i in range(attempts):
        tmp_path = None
        try:
            tmp_path = _safe_tmp(dir_for_state)
            with open(tmp_path, "w", encoding="utf-8") as tmp:
                json.dump(state, tmp, ensure_ascii=False, indent=2)
                tmp.flush()
                os.fsync(tmp.fileno())
            os.replace(tmp_path, STATE_PATH)  # atomar
            return
        except Exception as e:
            last_err = e
            logging.warning(f"State speichern Versuch {i+1}/{attempts} fehlgeschlagen: {e}")
            time.sleep(0.4 * (i + 1))
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
    raise RuntimeError(f"State konnte nicht gespeichert werden: {STATE_PATH} :: {last_err}")

# ======================================================
# Cloudflare / DNS
# ======================================================
def get_public_ip() -> Optional[str]:
    try:
        r = SESSION.get("https://api4.ipify.org?format=json", timeout=10)
        r.raise_for_status()
        return r.json()["ip"]
    except Exception as e:
        logging.warning(f"Öffentliche IP konnte nicht geholt werden: {e}")
        return None

def is_internet_available() -> bool:
    try:
        r = SESSION.get("https://www.google.com", timeout=8)
        return r.status_code == 200
    except Exception:
        return False

def get_zone_id(domain: str) -> Optional[str]:
    try:
        r = SESSION.get(f"{CLOUDFLARE_API_URL}/zones", params={"name": domain}, timeout=15)
        r.raise_for_status()
        data = r.json()
        if data.get("success") and data.get("result"):
            return data["result"][0]["id"]
    except Exception as e:
        logging.error(f"Zone-ID für {domain} fehlgeschlagen: {e}")
    return None

def find_dns_record(zone_id: str, name: str, rtype: str = "A") -> Tuple[Optional[str], Optional[str]]:
    try:
        r = SESSION.get(
            f"{CLOUDFLARE_API_URL}/zones/{zone_id}/dns_records",
            params={"type": rtype, "name": name},
            timeout=15
        )
        r.raise_for_status()
        data = r.json()
        if data.get("success") and data.get("result"):
            rec = data["result"][0]
            return rec["id"], rec.get("content")
    except Exception as e:
        logging.error(f"DNS-Record Lookup {rtype} {name} fehlgeschlagen: {e}")
    return None, None

def update_a_record(zone_id: str, record_id: str, fqdn: str, new_ip: str) -> bool:
    proxied = PROXIED_OVERRIDES.get(fqdn.lower(), PROXIED_DEFAULT)
    payload = {"type": "A", "name": fqdn, "content": new_ip, "ttl": 300, "proxied": proxied}
    try:
        r = SESSION.put(
            f"{CLOUDFLARE_API_URL}/zones/{zone_id}/dns_records/{record_id}",
            data=json.dumps(payload),
            timeout=20
        )
        ok = r.status_code < 300 and r.json().get("success", False)
        if ok:
            logging.info(f"A-Record aktualisiert: {fqdn} → {new_ip} (proxied={proxied})")
        else:
            logging.error(f"A-Record Update fehlgeschlagen für {fqdn}: {r.text}")
        return ok
    except Exception as e:
        logging.error(f"A-Record Update Exception für {fqdn}: {e}")
        return False

def get_spf_record(zone_id: str, name: str) -> Tuple[Optional[str], Optional[str]]:
    return find_dns_record(zone_id, name, rtype="TXT")

def merge_spf(current: str, ip: str) -> str:
    base = current or ""
    if not base.startswith("v=spf1"):
        return f"v=spf1 a mx ip4:{ip} ~all"
    tokens = base.split()
    needle = f"ip4:{ip}"
    if needle not in tokens:
        all_idx = next((i for i, t in enumerate(tokens) if t.endswith("all")), None)
        insert_pos = all_idx if all_idx is not None else len(tokens)
        tokens.insert(insert_pos, needle)
    return " ".join(tokens)

def update_spf(zone_id: str, root_name: str, public_ip: str) -> None:
    rec_id, content = get_spf_record(zone_id, root_name)
    if not rec_id:
        logging.info(f"Kein SPF-TXT für {root_name} gefunden – wird nicht automatisch angelegt.")
        return
    new_spf = merge_spf(content or "", public_ip)
    if new_spf == (content or ""):
        logging.info(f"SPF bereits aktuell für {root_name}.")
        return
    payload = {"type": "TXT", "name": root_name, "content": new_spf, "ttl": 300}
    try:
        r = SESSION.put(
            f"{CLOUDFLARE_API_URL}/zones/{zone_id}/dns_records/{rec_id}",
            data=json.dumps(payload),
            timeout=20
        )
        if r.status_code < 300 and r.json().get("success", False):
            logging.info(f"SPF aktualisiert für {root_name}: {new_spf}")
        else:
            logging.error(f"SPF Update fehlgeschlagen für {root_name}: {r.text}")
    except Exception as e:
        logging.error(f"SPF Update Exception für {root_name}: {e}")

# ======================================================
# Zeitsteuerung
# ======================================================
def should_force_update(last_force_date: Optional[str]) -> bool:
    now = datetime.now()
    if now.hour != FORCE_UPDATE_HOUR:
        return False
    today_str = date.today().isoformat()
    return last_force_date != today_str

def next_wakeup(now: datetime) -> float:
    t_poll = now + timedelta(seconds=CHECK_INTERVAL_SECONDS)
    next_force = now.replace(minute=0, second=0, microsecond=0)
    if now.hour >= FORCE_UPDATE_HOUR:
        next_force = next_force + timedelta(days=1)
    next_force = next_force.replace(hour=FORCE_UPDATE_HOUR)
    return max(1.0, min((t_poll - now).total_seconds(), (next_force - now).total_seconds()))

# ======================================================
# Main
# ======================================================
def main():
    state = load_state()
    last_known_ip: Optional[str] = state.get("last_known_ip")
    last_force_date: Optional[str] = state.get("last_force_date")

    logging.info(f"DNS Updater gestartet. STATE_DIR={STATE_DIR} | STATE_PATH={STATE_PATH} | LOG_PATH={LOG_PATH}")

    while True:
        if not is_internet_available():
            logging.warning(f"Kein Internet. Warte {RETRY_INTERVAL_SECONDS}s …")
            time.sleep(RETRY_INTERVAL_SECONDS)
            continue

        public_ip = get_public_ip()
        if not public_ip:
            logging.warning(f"Öffentliche IP unbekannt. Warte {RETRY_INTERVAL_SECONDS}s …")
            time.sleep(RETRY_INTERVAL_SECONDS)
            continue

        force_now = should_force_update(last_force_date)
        ip_changed = (public_ip != last_known_ip)

        logging.info(f"Aktuelle öffentliche IPv4: {public_ip} | geändert={ip_changed} | force={force_now}")

        if ip_changed or force_now:
            for entry in DOMAINS:
                zone_name = entry["zone"]
                a_records = entry.get("a_records", [])
                spf_update = entry.get("spf_update", False)

                logging.info(f"Verarbeite Zone: {zone_name}")
                zone_id = get_zone_id(zone_name)
                if not zone_id:
                    logging.error(f"Zone-ID nicht gefunden für {zone_name}")
                    continue

                # A-Records
                for fqdn in a_records:
                    rec_id, current_ip = find_dns_record(zone_id, fqdn, rtype="A")
                    if not rec_id:
                        logging.error(f"A-Record nicht gefunden: {fqdn}")
                        continue
                    if current_ip == public_ip and not force_now:
                        logging.info(f"Keine Änderung: {fqdn} bleibt {public_ip}")
                    else:
                        logging.info(f"Aktualisiere {fqdn}: {current_ip} → {public_ip}")
                        update_a_record(zone_id, rec_id, fqdn, public_ip)

                # SPF-Update nur am Zonen-Root
                if spf_update:
                    update_spf(zone_id, zone_name, public_ip)

            # State aktualisieren
            last_known_ip = public_ip
            state["last_known_ip"] = last_known_ip
            if force_now:
                state["last_force_date"] = date.today().isoformat()
                last_force_date = state["last_force_date"]
            save_state(state)

        # Sleep bis nächstes Ereignis
        now = datetime.now()
        sleep_seconds = next_wakeup(now)
        logging.info(f"Nächster Check in {int(sleep_seconds)}s (spätestens {FORCE_UPDATE_HOUR:02d}:00).")
        time.sleep(sleep_seconds)

# ======================================================
if __name__ == "__main__":
    main()
