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

from scanners.apk_analyzer import analyze_apk
from scanners.pe_analyzer import analyze_pe
from scanners.authenticode_windows import verify_authenticode
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

# --- Ikki kengaytma niqobi (masalan "video.mp4.apk", "hisobot.pdf.exe") ---
# Hujumchi foydalanuvchi ko'radigan "hujjat/media" kengaytmasi orqasiga
# bajariladigan/o'rnatiladigan kengaytmani yashiradi. Bunday nom qonuniy
# fayllarda deyarli uchramaydi - DETERMINISTIK signal.
_EXECUTABLE_EXTS = {
    "apk", "exe", "scr", "com", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "ps1", "msi", "jar", "lnk", "hta", "pif", "dll", "xapk", "apks",
}
_DECOY_EXTS = {
    "mp4", "mp3", "avi", "mkv", "mov", "wav", "3gp", "jpg", "jpeg", "png", "gif",
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "zip", "rar", "7z",
}

def check_double_extension(filename: Optional[str]) -> Optional[str]:
    """`nom.mp4.apk` kabi (media/hujjat kengaytmasi + bajariladigan kengaytma) nomni aniqlaydi.
    Topilsa tushuntirish matnini, aks holda None qaytaradi."""
    if not filename:
        return None
    base = filename.strip().replace("\\", "/").rsplit("/", 1)[-1].lower()
    parts = base.split(".")
    if len(parts) >= 3 and parts[-1].strip() in _EXECUTABLE_EXTS and parts[-2].strip() in _DECOY_EXTS:
        return (f"Ikki kengaytma niqobi: '.{parts[-2].strip()}.{parts[-1].strip()}' - fayl "
                f"'{parts[-2].strip()}' ko'rinishida, aslida bajariladigan/o'rnatiladigan '.{parts[-1].strip()}'")
    return None



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

    # 0) Ikki kengaytma niqobi (masalan "video.mp4.apk") - deterministik
    dbl = check_double_extension(name)
    if dbl:
        findings.append(dbl)
        apk = analyze_apk(filepath)
        if apk is not None:
            findings.extend(apk["findings"])
        return {"score": 100, "findings": findings, "verdict_hint": "malicious", "magic": magic_label}

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

    # 2b) Android paketi (APK): haqiqiy AXML manifest tahlili (scanners/apk_analyzer.py).
    # Ball >= 80 (zararli APK'larga xos KOMBINATSIYA: SMS + accessibility/overlay + yashirin ikona...)
    # - "malicious"; aks holda "suspicious" (kompyuterda APK odatiy emas).
    if magic_label == "ZIP" or file_ext in ("apk", "xapk", "apks"):
        apk = analyze_apk(filepath)
        if apk is not None:
            findings.extend(apk["findings"])
            verdict = "malicious" if apk["verdict_hint"] == "malicious" else "suspicious"
            return {"score": apk["score"], "findings": findings, "verdict_hint": verdict, "magic": magic_label or "ZIP"}

    # 3) Ehtimoliy (statistik) signallar
    soft = scan_bytes_heuristic(data, magic_label, file_ext)
    findings.extend(soft["findings"])
    score = soft["score"]

    # 3b) PE (.exe/.dll) chuqur statik tahlili: bo'limlar, importlar, paketlovchi (scanners/pe_analyzer.py)
    signed = False
    if magic_label == "PE":
        pe = analyze_pe(data)
        if pe is not None:
            signed = bool(pe.get("signed"))
            findings.extend(f for f in pe["findings"] if f not in findings)
            score = min(100, max(score, pe["score"]))

    # 3c) Windows Authenticode - HAQIQIY tasdiqlash (Get-AuthenticodeSignature, WinVerifyTrust).
    # Foydalanuvchi so'rovi: "tekshiruv natijasi hech qachon noma'lum qolmasligi kerak" - ko'p
    # Windows tizim fayli (endi agent BARCHA disklarni kuzatgani uchun) hash-intel bazasida
    # UMUMAN yo'q (kam tarqalgan, noyob) - lekin Microsoft tomonidan imzolangan bo'lsa, buni
    # DARHOL (tarmoqsiz) "toza, tasdiqlangan" deb belgilash mumkin. `pe_analyzer.py`ning
    # "signed" bayrog'idan farqli - bu yerda imzo YAROQLILIGI (sertifikat zanjiri + fayl
    # o'zgartirilmaganligi) HAQIQATAN tekshiriladi, faqat mavjudligi emas.
    trusted_signature = False
    if magic_label == "PE":
        sig = verify_authenticode(filepath)
        if sig is not None:
            if sig["status"] == "HashMismatch":
                # Imzolangan fayl KEYINCHALIK o'zgartirilgan - deyarli 100% zararlanish belgisi
                # (soxta-pozitiv xavfi juda past, qonuniy dastur bunday holatga tushmaydi).
                findings.append(
                    f"Authenticode: imzo bilan fayl mos kelmaydi (HashMismatch) - imzolangandan "
                    f"keyin o'zgartirilgan bo'lishi mumkin (imzolovchi: {sig.get('publisher') or 'nomalum'})"
                )
                return {"score": 100, "findings": findings, "verdict_hint": "malicious",
                        "magic": magic_label, "signed": signed, "trusted_signature": False}
            if sig["trusted_publisher"]:
                trusted_signature = True
                findings.append(f"Authenticode: imzo tasdiqlangan ({sig['publisher']})")

    if trusted_signature:
        # Haqiqiy tasdiqlangan Microsoft imzosi - yumshoq (statistik) signallarni (masalan
        # ba'zi qonuniy tizim/administrator vositalarida uchraydigan API kombinatsiyalari)
        # bekor qiladi. Yuqoridagi DETERMINISTIK tekshiruvlar (ikki kengaytma, PDF, APK) bu
        # nuqtaga UMUMAN yetib kelmaydi (ular oldinroq, alohida return bilan tugaydi) - shuning
        # uchun bu yerda "clean"ga qaytarish ularni chetlab o'tmaydi.
        return {"score": 0, "findings": findings, "verdict_hint": "clean", "magic": magic_label,
                "signed": signed, "trusted_signature": True}

    verdict_hint = "suspicious" if score >= SUSPICIOUS_SCORE_THRESHOLD else "clean"

    return {"score": score, "findings": findings, "verdict_hint": verdict_hint, "magic": magic_label,
            "signed": signed, "trusted_signature": False}
