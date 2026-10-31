"""Read-only certificate coverage and website TLS presentation for MeowHome.
Does not issue/renew certificates or alter DNS or VHost state.
"""
from __future__ import annotations
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def _dns(name: str) -> str:
    return str(name or "").strip().lower().rstrip(".")

def certificate_covers_hostname(hostname: str, dns_names: list[str] | tuple[str, ...]) -> bool:
    """A DNS wildcard covers exactly one label, never the zone apex."""
    host = _dns(hostname)
    if not host or host.startswith(".") or ".." in host:
        return False
    for entry in dns_names:
        name = _dns(entry)
        if name == host:
            return True
        if name.startswith("*.") and name.count("*") == 1:
            suffix = name[2:]
            if suffix and host.endswith("." + suffix):
                prefix = host[:-(len(suffix) + 1)]
                if prefix and "." not in prefix:
                    return True
    return False

def certificate_details(fullchain: Path, *, now: float | None = None) -> dict[str, Any]:
    info: dict[str, Any] = {
        "status": "unknown", "expires_at": "", "days_left": None, "dns_names": []
    }
    if not fullchain.is_file():
        info["status"] = "missing"
        return info
    try:
        decoded = ssl._ssl._test_decode_cert(str(fullchain))
        info["dns_names"] = sorted({
            _dns(value)
            for kind, value in decoded.get("subjectAltName", ())
            if kind == "DNS" and _dns(value)
        })
        not_after = decoded.get("notAfter")
        if not not_after:
            return info
        expiry = ssl.cert_time_to_seconds(not_after)
        seconds = expiry - (time.time() if now is None else now)
        info["days_left"] = int(seconds // 86400)
        info["expires_at"] = datetime.fromtimestamp(expiry, timezone.utc).strftime("%Y-%m-%d")
        info["status"] = "expired" if seconds <= 0 else "warning" if seconds < 30 * 86400 else "ok"
    except (OSError, ValueError, ssl.SSLError):
        pass
    return info

TLS_LABELS = {
    "ok": "TLS gültig",
    "warning": "Läuft bald ab",
    "expired": "Zertifikat abgelaufen",
    "missing": "Zertifikat fehlt",
    "unknown": "Zertifikat unprüfbar",
    "not_covered": "Domain nicht abgedeckt",
    "not_enabled": "HTTPS nicht aktiviert",
}

def site_tls_health(site: dict[str, Any], certificates: list[dict[str, Any]]) -> dict[str, Any]:
    record = dict(site)
    cert_by_name = {_dns(c.get("domain", "")): c for c in certificates}
    certificate = cert_by_name.get(_dns(site.get("cert_domain", "")))
    expected = [_dns(site.get("host", ""))]
    expected.extend(_dns(a) for a in (site.get("aliases") or []))
    expected = [n for n in dict.fromkeys(expected) if n]
    missing_hosts: list[str] = []
    if not site.get("tls"):
        status = "not_enabled"
    elif not site.get("cert_domain") or not certificate or certificate.get("status") == "missing":
        status = "missing"
    elif certificate.get("status") == "unknown":
        status = "unknown"
    elif certificate.get("status") == "expired":
        status = "expired"
    else:
        names = certificate.get("dns_names") or []
        missing_hosts = [h for h in expected if not certificate_covers_hostname(h, names)]
        status = "not_covered" if missing_hosts else str(certificate.get("status", "unknown"))
    record["tls_status"] = status
    record["tls_label"] = TLS_LABELS.get(status, "TLS unbekannt")
    record["tls_uncovered_hosts"] = missing_hosts
    record["tls_cert"] = certificate
    return record

def enrich_sites(sites: list[dict[str, Any]], certificates: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [site_tls_health(s, certificates) for s in sites]


def choose_covered_certificate(hostnames: list[str], certificates: list[dict[str, Any]]) -> str | None:
    """Select a usable existing certificate covering every hostname; never issue one."""
    expected = [_dns(h) for h in hostnames if _dns(h)]
    if not expected:
        return None
    candidates = [
        c for c in certificates
        if c.get("status") in {"ok", "warning"}
        and all(certificate_covers_hostname(h, c.get("dns_names") or []) for h in expected)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda c: (
        -sum(h in {_dns(n) for n in c.get("dns_names") or []} for h in expected),
        0 if c.get("status") == "ok" else 1,
        str(c.get("domain", "")),
    ))
    return str(candidates[0]["domain"])
