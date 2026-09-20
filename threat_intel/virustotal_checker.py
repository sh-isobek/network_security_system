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


def vt_slot_busy() -> bool:
    """
    API (agent so'rovi) yo'lida ISHLATILADI: VT bepul tarifi (4/min) slotini kutish agentni
    5s timeout'ga tushiradi - shuning uchun band bo'lsa VT so'ralmaydi (True), fayl fon
    tekshiruviga (`file_analysis_engine`) qoldiriladi.
    """
    return bool(VT_API_KEY) and time.time() - _last_request_time < RATE_LIMIT_DELAY


def check_virustotal(sha256: str, timeout: int = 10) -> Optional[dict]:
    """
    VirusTotal'dan hash bo'yicha natija so'raydi.

    Qaytaradi:
        {"malicious": bool, "threat_name": str, "positives": int, "total": int}
        - FAQAT VT bu hash haqida HAQIQIY tahlil ma'lumotiga ega bo'lsa
        (ya'ni "scanned" - fayl VT bazasida bor VA kamida bitta dvigatel
        uni tekshirgan). Bu holatda `malicious=False` HAQIQIY "toza"
        signalidir (VT ko'rgan, hech qaysi dvigatel belgilamagan).

        Aks holda `None` qaytaradi - bu quyidagi holatlarning BARCHASINI
        qamraydi: API kalit yo'q, tarmoq xatosi, rate limit, VA (MUHIM,
        ilgari xato bo'lgan holat) hash VT bazasida UMUMAN topilmagan
        (404). `None` HECH QACHON "toza" deb talqin qilinmasligi kerak -
        chaqiruvchi (`file_analysis_engine.py`/`api/server.py`) buni
        "hali tekshirilmagan / ma'lumot yo'q" (unknown) deb hisoblashi
        SHART, aks holda tarmoqqa yangi (VT hali ko'rmagan) zararli
        dastur "toza" deb noto'g'ri belgilanib qoladi - bu real
        production xavfsizlik xatosi edi (avval 404 -> `malicious=False`
        qaytarardi, bu "VT ko'rdi va toza deb topdi" bilan bir xil
        ko'rinardi, garchi VT bu haqida UMUMAN hech narsa bilmasa ham).
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
        # MUHIM (real production xatosi tuzatilgan): VT bu hash haqida
        # HECH NARSA bilmaydi - bu "toza" degani EMAS, "ma'lumot yo'q"
        # degani. Avval bu yerda `{"malicious": False, ...}` qaytarilib,
        # chaqiruvchi tomonidan "VT toza deb topdi" bilan bir xil
        # ko'rilardi.
        return None

    if resp.status_code != 200:
        return None  # rate limit yoki boshqa xatolik

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    total = sum(stats.values()) if stats else 0

    if total == 0:
        # VT bazasida yozuv bor, lekin hali birorta dvigatel tomonidan
        # tekshirilmagan (masalan endigina yuklangan, tahlil navbatda) -
        # bu ham "toza" emas, "hali ma'lumot yo'q".
        return None

    malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)

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
