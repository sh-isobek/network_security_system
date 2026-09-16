"""
ThreatFox (abuse.ch) - so'nggi IOC (Indicator of Compromise) feed'i.

URLhaus bilan bir xil naqsh: bepul, lekin https://auth.abuse.ch/ orqali
olinadigan "Auth-Key" talab qiladi (`THREATFOX_AUTH_KEY`). Bo'sh bo'lsa
`fetch_recent_iocs()` `None` qaytaradi.

API hujjati: https://threatfox.abuse.ch/api/
"""
import logging
import os

import requests

logger = logging.getLogger("threatfox_feed")

THREATFOX_API_URL = "https://threatfox-api.abuse.ch/api/v1/"

# BlacklistEntry (IP/domen) uchun mos IOC turlari - hash turlari
# (masalan "md5_hash", "sha256_hash") ATAYLAB o'tkazib yuboriladi,
# ular HashBlacklist jadvaliga tegishli (alohida, keyingi ish).
RELEVANT_IOC_TYPES = {"domain", "url", "ip:port"}


def is_configured() -> bool:
    return bool(os.getenv("THREATFOX_AUTH_KEY", ""))


def _extract_value(ioc: str, ioc_type: str) -> str:
    """`ip:port` turidagi IOC'dan faqat IP qismini ajratadi - loyihada
    IP'lar BlacklistEntry'da porti'siz, aniq moslik bo'yicha saqlanadi."""
    if ioc_type == "ip:port" and ":" in ioc:
        return ioc.rsplit(":", 1)[0]
    if ioc_type == "url":
        # BlacklistEntry domen/IP ro'yxati - to'liq URL emas, host qismi kerak.
        from urllib.parse import urlparse
        parsed = urlparse(ioc if "://" in ioc else f"http://{ioc}")
        return parsed.hostname or ioc
    return ioc


def fetch_recent_iocs(days: int = 1):
    """
    So'nggi `days` kunlik IOC'larni qaytaradi (domain/url/ip:port
    turlaridan, mos `value`ga normallashtirilgan holda).

    Har biri: {"value", "ioc_type", "malware", "confidence_level",
    "first_seen", "reference"} kalitlariga ega dict. Kalit sozlanmagan
    yoki so'rov muvaffaqiyatsiz bo'lsa - `None`.
    """
    auth_key = os.getenv("THREATFOX_AUTH_KEY", "")
    if not auth_key:
        return None

    try:
        resp = requests.post(
            THREATFOX_API_URL,
            headers={"Auth-Key": auth_key},
            json={"query": "get_iocs", "days": days},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error(f"ThreatFox so'rovida xatolik: {exc}")
        return None
    except ValueError as exc:
        logger.error(f"ThreatFox javobini JSON sifatida o'qib bo'lmadi: {exc}")
        return None

    query_status = data.get("query_status")
    if query_status == "no_results":
        return []
    if query_status != "ok":
        logger.warning(f"ThreatFox query_status='{query_status}' - kutilmagan javob")
        return None

    items = data.get("data") or []
    results = []
    for item in items:
        ioc_type = item.get("ioc_type")
        ioc = item.get("ioc")
        if ioc_type not in RELEVANT_IOC_TYPES or not ioc:
            continue
        value = _extract_value(ioc, ioc_type)
        if not value:
            continue
        results.append({
            "value": value,
            "ioc_type": ioc_type,
            "malware": item.get("malware_printable") or item.get("malware"),
            "confidence_level": item.get("confidence_level"),
            "first_seen": item.get("first_seen"),
            "reference": item.get("reference"),
        })
    return results
