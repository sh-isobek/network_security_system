"""
URLhaus (abuse.ch) - so'nggi zararli URL'lar feed'i.

2024'dan buyon bepul, lekin https://auth.abuse.ch/ orqali ro'yxatdan
o'tib olinadigan "Auth-Key" talab qiladi (`URLHAUS_AUTH_KEY` muhit
o'zgaruvchisi). Kalit sozlanmagan bo'lsa, `fetch_recent_urls()` `None`
qaytaradi - chaqiruvchi buni "feed o'chiq" deb, xatosiz o'tkazib
yuborishi kerak.

API hujjati: https://urlhaus-api.abuse.ch/
"""
import logging
import os

import requests

logger = logging.getLogger("urlhaus_feed")

URLHAUS_API_URL = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/{limit}/"


def is_configured() -> bool:
    return bool(os.getenv("URLHAUS_AUTH_KEY", ""))


def fetch_recent_urls(limit: int = 1000):
    """
    So'nggi (oxirgi 3 kunlik, max 1000 ta) zararli URL'larni qaytaradi.

    Har biri: {"url", "host", "url_status", "threat", "date_added",
    "urlhaus_reference"} kalitlariga ega dict. Kalit sozlanmagan yoki
    so'rov muvaffaqiyatsiz bo'lsa - `None` (bo'sh ro'yxat EMAS, "hech
    narsa topilmadi" bilan "manba o'chiq/xato berdi"ni farqlash uchun).
    """
    auth_key = os.getenv("URLHAUS_AUTH_KEY", "")
    if not auth_key:
        return None

    try:
        resp = requests.get(
            URLHAUS_API_URL.format(limit=limit),
            headers={"Auth-Key": auth_key},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException as exc:
        logger.error(f"URLhaus so'rovida xatolik: {exc}")
        return None
    except ValueError as exc:
        logger.error(f"URLhaus javobini JSON sifatida o'qib bo'lmadi: {exc}")
        return None

    query_status = data.get("query_status")
    if query_status == "no_results":
        return []
    if query_status != "ok":
        logger.warning(f"URLhaus query_status='{query_status}' - kutilmagan javob")
        return None

    urls = data.get("urls") or []
    results = []
    for item in urls:
        host = item.get("host")
        if not host:
            continue
        results.append({
            "host": host,
            "url": item.get("url"),
            "url_status": item.get("url_status"),
            "threat": item.get("threat"),
            "date_added": item.get("date_added"),
            "urlhaus_reference": item.get("urlhaus_reference"),
        })
    return results
