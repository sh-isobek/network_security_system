"""
Fayl turi aniqlash (magic bytes) - foydalanuvchi chuqur arxitektura
tahlilidagi ⑳-band.

MUHIM (real bo'shliq): loyihada `FileEvent.file_ext` HAR DOIM fayl
NOMIning o'zidan (`filename.rsplit(".", 1)[-1]`) olinardi - bu esa
hujumchi to'liq nazorat qiladigan qiymat. Masalan `invoice.pdf.exe`
yoki `payload.zip`ni `report.docx` deb nomlash orqali, tizim buni
"PDF"/"DOCX" deb hisoblardi - garchi Suricata `force-magic: yes`
orqali haqiqiy fayl turini (`FileEvent.magic`) ALLAQACHON aniqlab
bergan bo'lsa ham, bu ma'lumot HECH QAYERDA extension bilan
solishtirilmasdi (faqat bazaga yozilardi, tahlil qilinmasdi).

Bu modul ikki narsa qiladi:
  1. Haqiqiy fayl baytlaridan (`detect_magic_from_bytes`/`_from_file`)
     yoki Suricata'ning libmagic matn natijasidan (`detect_magic_
     from_text`) xavfsizlik nuqtai nazaridan MUHIM toifani (PE/ELF/
     ZIP/PDF/OLE2/SCRIPT/...) aniqlaydi - to'liq libmagic KUTUBXONASI
     ISHLATILMAYDI (tashqi bog'liqlik yo'q, faqat eng muhim, keng
     tanilgan signature'lar) - bu ataylab, xuddi loyihaning boshqa
     joylarida ham (masalan `net-snmp` CLI `pysnmp` o'rniga) qilingani
     kabi, sodda va ishonchli yechim.
  2. `check_extension_mismatch()` - fayl kengaytmasi bilan haqiqiy
     turini solishtirib, "niqoblangan" (masalan .pdf deb ko'rsatilgan,
     aslida PE32 bajariladigan fayl) holatlarni aniqlaydi.

ATAYLAB QILINMAGAN (halol cheklov): to'liq libmagic-darajasidagi
signature bazasi (minglab format) - faqat xavfsizlik nuqtai nazaridan
eng muhim, keng tarqalgan turlar qamrab olingan.
"""
import re

# --- Bayt-signature jadvali (offset 0 dan) - eng muhim, xavfsizlik
# nuqtai nazaridan tez-tez uchraydigan turlar ---
_BYTE_SIGNATURES = [
    (b"MZ", "PE"),                                  # Windows EXE/DLL
    (b"\x7fELF", "ELF"),                             # Linux/Unix bajariladigan
    (b"PK\x03\x04", "ZIP"),                          # ZIP (shu jumladan docx/xlsx/pptx/jar/apk)
    (b"PK\x05\x06", "ZIP"),                          # bo'sh ZIP
    (b"PK\x07\x08", "ZIP"),                          # spanned ZIP
    (b"%PDF", "PDF"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "OLE2"),   # eski .doc/.xls/.ppt, .msi
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xBC\xAF\x27\x1C", "7Z"),
    (b"\x1f\x8b", "GZIP"),
    (b"\xCA\xFE\xBA\xBE", "MACHO"),
    (b"\xCE\xFA\xED\xFE", "MACHO"),
    (b"\xCF\xFA\xED\xFE", "MACHO"),
    (b"\xFF\xD8\xFF", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"#!", "SCRIPT"),                               # shebang (sh/python/perl/...)
]

# --- Suricata'ning libmagic matn natijasidan (`fileinfo.magic`) ---
_TEXT_MAGIC_PATTERNS = [
    (re.compile(r"PE32|MS-DOS executable", re.IGNORECASE), "PE"),
    (re.compile(r"\bELF\b", re.IGNORECASE), "ELF"),
    (re.compile(r"Zip archive|Java archive|Office Open XML|Microsoft (Word|Excel|PowerPoint) 2007", re.IGNORECASE), "ZIP"),
    (re.compile(r"PDF document", re.IGNORECASE), "PDF"),
    (re.compile(r"Composite Document File|CDF V2 Document|MSI Installer", re.IGNORECASE), "OLE2"),
    (re.compile(r"RAR archive", re.IGNORECASE), "RAR"),
    (re.compile(r"7-zip archive", re.IGNORECASE), "7Z"),
    (re.compile(r"gzip compressed", re.IGNORECASE), "GZIP"),
    (re.compile(r"shell script|Python script|Perl script|script text executable", re.IGNORECASE), "SCRIPT"),
    (re.compile(r"Mach-O", re.IGNORECASE), "MACHO"),
    (re.compile(r"JPEG image", re.IGNORECASE), "JPEG"),
    (re.compile(r"PNG image", re.IGNORECASE), "PNG"),
]

# Kengaytma -> shu kengaytma uchun "normal" hisoblanadigan magic toifalar.
# Bu yerda YO'Q kengaytmalar (masalan .txt, .csv, .log) uchun hech qanday
# fikr yuritilmaydi - ular istalgan tarkibga ega bo'lishi "normal"
# (masalan .txt fayl konfiguratsiya, log yoki har qanday matn bo'lishi
# mumkin - haqiqiy xavf faqat EXPECTED ro'yxatidagi "xavfsiz" toifa
# o'rniga bajariladigan fayl chiqqanda).
EXPECTED_MAGIC_FOR_EXT = {
    "exe": {"PE"}, "dll": {"PE"}, "scr": {"PE"}, "com": {"PE"},
    "msi": {"OLE2", "PE"},
    "zip": {"ZIP"}, "docx": {"ZIP"}, "xlsx": {"ZIP"}, "pptx": {"ZIP"},
    "docm": {"ZIP"}, "xlsm": {"ZIP"}, "pptm": {"ZIP"}, "jar": {"ZIP"}, "apk": {"ZIP"},
    "doc": {"OLE2"}, "xls": {"OLE2"}, "ppt": {"OLE2"},
    "pdf": {"PDF"},
    "rar": {"RAR"},
    "7z": {"7Z"},
    "gz": {"GZIP"}, "gzip": {"GZIP"},
    "jpg": {"JPEG"}, "jpeg": {"JPEG"},
    "png": {"PNG"},
}

# Bu toifalar - qanday kengaytma bo'lishidan qat'iy nazar - HAR DOIM
# "bajariladigan/skript" degani, shuning uchun "xavfsiz" deb kutilgan
# kengaytma (masalan .pdf/.jpg/.txt) ostida chiqsa, bu ANIQ niqoblash
# signali.
DANGEROUS_MAGIC = {"PE", "ELF", "SCRIPT", "MACHO"}


def detect_magic_from_bytes(header: bytes):
    """Fayl boshidagi baytlardan xavfsizlik nuqtai nazaridan muhim
    toifani aniqlaydi (PE/ELF/ZIP/PDF/...), aks holda None."""
    if not header:
        return None
    for signature, label in _BYTE_SIGNATURES:
        if header.startswith(signature):
            return label
    return None


def detect_magic_from_file(filepath: str, read_bytes: int = 64):
    """Haqiqiy fayldan (masalan Suricata `file-store`dan) birinchi
    baytlarni o'qib, toifani aniqlaydi. Fayl o'qib bo'lmasa (mavjud
    emas/ruxsat yo'q) xavfsiz tarzda None qaytaradi."""
    try:
        with open(filepath, "rb") as f:
            header = f.read(read_bytes)
    except OSError:
        return None
    return detect_magic_from_bytes(header)


def detect_magic_from_text(magic_text: str):
    """Suricata'ning libmagic matn natijasidan (masalan 'PE32
    executable (GUI) Intel 80386, for MS Windows') toifani aniqlaydi."""
    if not magic_text:
        return None
    for pattern, label in _TEXT_MAGIC_PATTERNS:
        if pattern.search(magic_text):
            return label
    return None


def check_extension_mismatch(file_ext: str, magic_label: str) -> dict:
    """
    Fayl kengaytmasi bilan haqiqiy (magic orqali aniqlangan) turini
    solishtiradi.

    Qaytaradi: {"mismatch": bool, "severity": "critical"|"medium"|None, "note": str|None}

    - Kengaytma EXPECTED_MAGIC_FOR_EXT'da yo'q (masalan .txt, .log,
      yoki umuman kengaytmasiz) - fikr yuritilmaydi (mismatch=False),
      chunki bunday fayllar tabiiy ravishda turli tarkibga ega bo'lishi
      mumkin.
    - Magic aniqlanmagan (None) - fikr yuritilmaydi.
    - Kengaytma "xavfsiz" turni kutadi (masalan .pdf -> PDF), lekin
      haqiqiy tarkib DANGEROUS_MAGIC'dan (bajariladigan/skript) -
      "critical" (aniq niqoblash signali).
    - Kengaytma boshqa (bajariladigan bo'lmagan) turni kutadi, lekin
      mos kelmadi (masalan .docx deb ko'rsatilgan, aslida OLE2/eski
      .doc) - "medium" (shubhali, lekin hujum signali unchalik aniq
      emas - fayl kengaytmasi shunchaki noto'g'ri bo'lishi ham mumkin).
    """
    if not magic_label:
        return {"mismatch": False, "severity": None, "note": None}

    ext = (file_ext or "").lower().lstrip(".")
    expected = EXPECTED_MAGIC_FOR_EXT.get(ext)
    if expected is None:
        return {"mismatch": False, "severity": None, "note": None}

    if magic_label in expected:
        return {"mismatch": False, "severity": None, "note": None}

    expected_str = "/".join(sorted(expected))
    if magic_label in DANGEROUS_MAGIC:
        return {
            "mismatch": True,
            "severity": "critical",
            "note": (
                f"Fayl kengaytmasi '.{ext}' ({expected_str} kutilgan), lekin haqiqiy tarkib "
                f"'{magic_label}' (BAJARILADIGAN FAYL!) - fayl NIQOBLANGAN bo'lishi mumkin"
            ),
        }
    return {
        "mismatch": True,
        "severity": "medium",
        "note": f"Fayl kengaytmasi '.{ext}' ({expected_str} kutilgan), lekin haqiqiy tarkib '{magic_label}'",
    }
