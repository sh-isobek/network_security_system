"""
Office Macro Scanner - DOC/DOCX/DOCM/XLS/XLSX/XLSM/PPT/PPTM fayllaridagi
VBA makroslarni aniqlaydi va xavfli buyruqlarni (Shell, CreateObject,
AutoOpen va h.k.) qidiradi.

oletools kutubxonasining olevba moduli - sanoat standarti hisoblanadi
(CERT-EU, ko'plab SOC jamoalari foydalanadi).
"""
import os
from typing import Optional

from oletools.olevba import VBA_Parser

# Xavfli deb hisoblanadigan VBA keyword'lari (olevba avtomatik aniqlaydigan
# "Suspicious" tur qatoriga qo'shimcha, o'zimiz ham tekshiramiz)
DANGEROUS_KEYWORDS = [
    "Shell", "WScript.Shell", "CreateObject", "Environ(",
    "AutoOpen", "AutoExec", "Document_Open", "Auto_Open",
    "URLDownloadToFile", "Kill", "RegWrite",
]


OFFICE_EXTENSIONS = {"doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf"}


def scan_office_file(filepath: str) -> Optional[dict]:
    """
    Office faylini tekshiradi.

    Qaytaradi:
        None - agar fayl Office formatida bo'lmasa yoki makro bo'lmasa
        {"has_macro": bool, "suspicious": bool, "findings": [...]}
    """
    if not os.path.isfile(filepath):
        return None

    # Muhim: VBA_Parser ba'zan Office bo'lmagan (masalan matn/JSON) fayllarni
    # ham "parslash mumkin" deb noto'g'ri xulosa chiqarishi mumkin, shuning
    # uchun avval kengaytma bo'yicha filtrlaymiz - soxta musbat natijalarni
    # oldini olish uchun zarur qadam.
    ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
    if ext not in OFFICE_EXTENSIONS:
        return None

    try:
        parser = VBA_Parser(filepath)
    except Exception:
        return None  # Office formatida emas yoki o'qib bo'lmadi

    if not parser.detect_vba_macros():
        parser.close()
        return {"has_macro": False, "suspicious": False, "findings": []}

    findings = []
    suspicious = False

    try:
        for (filename, stream_path, vba_filename, vba_code) in parser.extract_macros():
            if not vba_code:
                continue
            for keyword in DANGEROUS_KEYWORDS:
                if keyword.lower() in vba_code.lower():
                    findings.append(f"Xavfli VBA buyruq: {keyword} ({vba_filename})")
                    suspicious = True
    finally:
        parser.close()

    return {"has_macro": True, "suspicious": suspicious, "findings": findings}
