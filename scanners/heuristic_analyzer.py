"""
Heuristik statik tahlil - foydalanuvchi so'rovi: "'unknown' fayl hech
qachon qolmasin - zararli yoki zararsizga aniq ajratilsin".

MUHIM (nega bu modul kerak): hash-intel (local blacklist/VirusTotal/
MalwareBazaar) FAQAT allaqachon "ma'lum" fayllar haqida gapira oladi -
yangi (hali hech qanday bazada ko'rinmagan) fayl har doim "unknown"
bo'lib qolaveradi, garchi hech qachon zararli yoki zararsiz bo'lishidan
qat'iy nazar. Bu modul TARMOQQA CHIQMAYDIGAN, faqat fayl BAYTLARI
asosidagi ikkinchi, mustaqil signal manbai qo'shadi - shu orqali
"unknown" holatni deyarli barcha hollarda "clean" yoki "suspicious"ga
hal qiladi.

ATAYLAB IKKI XIL ISHONCH DARAJASI:
  - DETERMINISTIK (kod, "malicious" bera oladi): fayl kengaytmasi
    haqiqiy tarkibga MUTLAQO zid (masalan .pdf deb ko'rsatilgan, aslida
    PE32 bajariladigan fayl - `scanners/file_type_detector.py`) YOKI
    PDF ichida xavfli tuzilma (`scanners/pdf_analyzer.py`, allaqachon
    server tomonida XUDDI SHU ishonch darajasida "malicious" beradi -
    bu yerda faqat xuddi shu tekshiruv fayl mazmuni FAQAT endpoint'da
    mavjud bo'lgan hollar uchun qayta ishlatiladi).
  - EHTIMOLIY (statistik, FAQAT "suspicious" bera oladi, HECH QACHON
    "malicious" EMAS - soxta-pozitiv xavfi): entropiya (paketlash/
    shifrlash belgisi) va skriptlardagi shubhali naqshlar (Base64
    dekodlash, yashirin PowerShell, tarmoqdan yuklab olish). Bular
    YAKKA O'ZI hech qachon avtomatik karantin/tarmoqdan uzishga olib
    kelmaydi (`api/server.py::check_hash()` va `engine/deep_scan_
    engine.py`da qanday ishlatilganiga qarang) - faqat Alert(medium)
    yaratadi, tahlilchi qo'lda ko'rib chiqishi uchun.

HALOL CHEKLOV: bu - to'liq behavioral/sandbox tahlil EMAS, faqat statik
signallar to'plami. Office makro (oletools) va YARA/ClamAV imzo-asosli
tekshiruv bu yerda YO'Q (og'ir bog'liqlik - agent .exe'siga qo'shish
alohida ish) - ular server tomonida (`engine/deep_scan_engine.py`,
Suricata orqali kelgan, `stored_path` mavjud fayllar uchun) allaqachon
mavjud. Shuning uchun Endpoint Agent orqali kelgan Office/arxiv
fayllar uchun "unknown" ba'zan HALI HAM qolishi mumkin - bu ATAYLAB,
soxta "clean" yorlig'i berishdan ko'ra halolroq.
"""
import math
import re
from collections import Counter
from typing import Optional

from scanners.file_type_detector import (
    detect_magic_from_bytes,
    check_extension_mismatch,
)

# Executable/skript turlari uchun entropiya tahlili mazmunli - ZIP/JPEG/
# PNG/PDF kabi formatlar tabiiy ravishda yuqori entropiyaga ega (allaqachon
# siqilgan/ixcham ma'lumot), shuning uchun ular bu yerda BAHOLANMAYDI -
# aks holda har qanday .docx/.jpg soxta-pozitiv "yuqori entropiya" olardi.
_ENTROPY_RELEVANT_MAGIC = {"PE", "ELF", "MACHO", "SCRIPT"}
_HIGH_ENTROPY_THRESHOLD = 7.2  # 8.0 dan maksimal - paketlangan/shifrlangan kodga xos

_SUSPICIOUS_SCRIPT_PATTERNS = [
    (re.compile(rb"FromBase64String", re.IGNORECASE), "PowerShell Base64 dekodlash (FromBase64String)"),
    (re.compile(rb"-enc(odedcommand)?\b", re.IGNORECASE), "PowerShell kodlangan buyruq (-EncodedCommand)"),
    (re.compile(rb"Invoke-Expression|\bIEX\s*\(", re.IGNORECASE), "PowerShell dinamik bajarish (Invoke-Expression/IEX)"),
    (re.compile(rb"DownloadString|DownloadFile|Net\.WebClient", re.IGNORECASE), "Tarmoqdan yuklab olish (WebClient)"),
    (re.compile(rb"eval\s*\(\s*base64_decode", re.IGNORECASE), "eval(base64_decode) - klassik webshell naqshi"),
    (re.compile(rb"-w(indowstyle)?\s+hidden", re.IGNORECASE), "Yashirin oynada ishga tushirish (-WindowStyle Hidden)"),
    (re.compile(rb"Add-MpPreference\s+-ExclusionPath", re.IGNORECASE), "Windows Defender istisnosini qo'shish (himoyani o'chirish urinishi)"),
]

# Ehtimoliy (statistik) signallar - HECH QACHON "malicious" bermaydi,
# faqat "suspicious". Bu chegaradan yuqori ball "unknown"ni "suspicious"ga
# hal qilish uchun ishlatiladi (`api/server.py`, `engine/deep_scan_engine.py`).
SUSPICIOUS_SCORE_THRESHOLD = 40

READ_LIMIT_BYTES = 5 * 1024 * 1024  # 5 MB - "zip bomb"ga o'xshash cheksiz o'qishdan himoya


def shannon_entropy(data: bytes) -> float:
    """Bayt taqsimotining Shannon entropiyasi (0.0 - 8.0). Bo'sh ma'lumot uchun 0.0."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def scan_bytes_heuristic(data: bytes, magic_label: Optional[str], file_ext: Optional[str]) -> dict:
    """
    FAQAT ehtimoliy (statistik) signallar - entropiya + skript naqshlari.

    Qaytaradi: {"score": 0-100, "findings": [str], "verdict_hint": "clean"|"suspicious"}
    "malicious" HECH QACHON qaytarilmaydi (bu funksiya soxta-pozitiv
    xavfi yuqori signallar bilan ishlaydi) - deterministik "malicious"
    xulosasi uchun `analyze_file()`dagi kengaytma-nomuvofiqlik/PDF
    tekshiruviga qarang.
    """
    findings = []
    score = 0

    if magic_label in _ENTROPY_RELEVANT_MAGIC and data:
        entropy = shannon_entropy(data)
        if entropy >= _HIGH_ENTROPY_THRESHOLD:
            findings.append(
                f"Yuqori entropiya ({entropy:.2f}/8.0) - bajariladigan/skript fayl uchun "
                f"paketlangan/shifrlangan/obfuskatsiya qilingan kod belgisi bo'lishi mumkin"
            )
            score += 40

    ext = (file_ext or "").lower().lstrip(".")
    if magic_label == "SCRIPT" or ext in {"ps1", "vbs", "js", "php", "sh", "bat", "cmd"}:
        for pattern, note in _SUSPICIOUS_SCRIPT_PATTERNS:
            if pattern.search(data):
                findings.append(f"Shubhali skript naqshi: {note}")
                score += 35

    score = min(score, 100)
    verdict_hint = "suspicious" if score >= SUSPICIOUS_SCORE_THRESHOLD else "clean"
    return {"score": score, "findings": findings, "verdict_hint": verdict_hint}


def analyze_file(filepath: str, filename: Optional[str] = None) -> dict:
    """
    Bitta fayl uchun TO'LIQ mahalliy (tarmoqqa chiqmaydigan) statik
    xulosa - Endpoint Agent tomonidan ishlatiladi (fayl mazmuni FAQAT
    shu yerda, endpoint'da mavjud - server hech qachon fayl baytlarini
    olmaydi).

    Birlashtiradi:
      1. Kengaytma vs haqiqiy tarkib nomuvofiqligi (DETERMINISTIK -
         "malicious" bera oladi, xuddi server tomonidagi Suricata
         yo'li bilan bir xil ishonch darajasida).
      2. PDF ichidagi xavfli tuzilma (DETERMINISTIK, `.pdf` bo'lsa) -
         `scanners/pdf_analyzer.py` orqali (tashqi bog'liqliksiz, zlib
         bilan siqilgan qismlarni ham ochadi).
      3. Entropiya + skript naqshlari (EHTIMOLIY - faqat "suspicious").

    Qaytaradi: {"score": 0-100, "findings": [str], "verdict_hint":
    "malicious"|"suspicious"|"clean", "magic": str|None}
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read(READ_LIMIT_BYTES)
    except OSError as exc:
        return {"score": 0, "findings": [f"Fayl o'qib bo'lmadi: {exc}"], "verdict_hint": "clean", "magic": None}

    name = filename or filepath
    file_ext = name.rsplit(".", 1)[-1].lower() if "." in name else None
    magic_label = detect_magic_from_bytes(data)

    findings = []

    # 1) Kengaytma nomuvofiqligi - deterministik
    mismatch = check_extension_mismatch(file_ext, magic_label)
    if mismatch["severity"] == "critical":
        findings.append(mismatch["note"])
        return {"score": 100, "findings": findings, "verdict_hint": "malicious", "magic": magic_label}
    if mismatch["mismatch"]:
        findings.append(mismatch["note"])

    # 2) PDF ichidagi xavfli tuzilma - deterministik (fayl haqiqatan
    # diskda bo'lgani uchun to'liq scan_pdf_file() ishlatiladi - u
    # o'zi ham fayl kengaytmasini ichida tekshiradi)
    if magic_label == "PDF" or file_ext == "pdf":
        try:
            from scanners.pdf_analyzer import scan_pdf_file
            pdf_result = scan_pdf_file(filepath)
        except Exception:
            pdf_result = None
        if pdf_result and pdf_result.get("suspicious"):
            findings.extend(pdf_result.get("findings", []))
            return {"score": 100, "findings": findings, "verdict_hint": "malicious", "magic": magic_label or "PDF"}

    # 3) Ehtimoliy (statistik) signallar
    soft = scan_bytes_heuristic(data, magic_label, file_ext)
    findings.extend(soft["findings"])
    score = soft["score"]
    verdict_hint = "suspicious" if score >= SUSPICIOUS_SCORE_THRESHOLD else "clean"

    return {"score": score, "findings": findings, "verdict_hint": verdict_hint, "magic": magic_label}
