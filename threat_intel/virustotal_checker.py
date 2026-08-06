"""
VirusTotal API v3 orqali fayl hash'ini tekshirish.

MUHIM (Rate Limit): VirusTotal bepul (public) API kaliti daqiqasiga
4 so'rov, kuniga 500 so'rov bilan cheklangan. Shuning uchun:
  1. Har doim avval local_checker.check_local() ishlatiladi.
  2. Bu modul so'rovlar orasida majburiy pauza qo'yadi (RATE_LIMIT_DELAY).
  3. Natija darhol hash_blacklist jadvaliga yoziladi - xuddi shu hash
     ikkinchi marta VT'ga so'ralmaydi.

API kalitini olish: https://www.virustotal.com/gui/my-apikey
.env faylida VT_API_KEY=... qilib kiriting.
"""
import os
import sys
import time
from typing import Optional

import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"
RATE_LIMIT_DELAY = 15  # soniya - bepul tarif uchun xavfsiz oraliq (4/min)

_last_request_time = 0.0


def _respect_rate_limit():
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        time.sleep(RATE_LIMIT_DELAY - elapsed)
    _last_request_time = time.time()


def check_virustotal(sha256: str, timeout: int = 10) -> Optional[dict]:
    """
    VirusTotal'dan hash bo'yicha natija so'raydi.

    Qaytaradi:
        {"malicious": bool, "threat_name": str, "positives": int, "total": int}
        yoki API kaliti yo'q/xatolik bo'lsa None (bu holda tizim boshqa
        manbaga - MalwareBazaar yoki local blacklist'ga - tayanadi).
    """
    if not VT_API_KEY:
        return None  # API kalit sozlanmagan - bu manba o'tkazib yuboriladi

    _respect_rate_limit()

    try:
        resp = requests.get(
            f"{VT_BASE_URL}/{sha256}",
            headers={"x-apikey": VT_API_KEY},
            timeout=timeout,
        )
    except requests.RequestException:
        return None  # tarmoq xatoligi - keyingi tsiklda qayta urinib ko'riladi

    if resp.status_code == 404:
        return {"malicious": False, "threat_name": None, "positives": 0, "total": 0}

    if resp.status_code != 200:
        return None  # rate limit yoki boshqa xatolik

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0

    # Threat nomini birinchi "malicious" deb topgan dvigatel natijasidan olamiz
    results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    threat_name = None
    for engine_result in results.values():
        if engine_result.get("category") == "malicious":
            threat_name = engine_result.get("result")
            break

    return {
        "malicious": malicious_count > 0,
        "threat_name": threat_name,
        "positives": malicious_count,
        "total": total,
    }
