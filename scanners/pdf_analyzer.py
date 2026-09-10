"""
PDF chuqur tahlil - foydalanuvchi chuqur arxitektura tahlilidagi
⑲-band ("PDF scanner alohida modul bo'lishi kerak").

MUHIM (real bo'shliq): PDF fayllar avval FAQAT YARA qoidalari orqali
(`/JavaScript`, `/Launch`, `/EmbeddedFile`, `/OpenAction` kabi kalit
so'zlarni XOM, siqilmagan baytlarda qidirish orqali) tekshirilardi.
Zamonaviy PDF'larning aksariyati o'z ichki obyektlarini (shu jumladan
aynan xavfli `/OpenAction`/`/JavaScript` lug'atlarining O'ZINI ham)
FlateDecode (zlib) bilan SIQIB saqlaydi - bu holatda oddiy xom-bayt
qidiruvi HECH NARSA topa olmaydi (siqilgan bayt oqimi ichida `/Launch`
kabi matn tasodifan mavjud bo'lishi extremely kam ehtimol).

Bu modul, tashqi kutubxonasiz (`zlib` - Python standart kutubxonasi):
  1. PDF ichidagi HAR BIR `stream...endstream` blokini FlateDecode
     bilan ochishga urinadi (xavfsizlik hajm chegaralari bilan -
     "zlib bomb"dan himoya, `scanners/archive_scanner.py`dagi
     zip-bomb himoyasi bilan bir xil naqsh).
  2. Xom VA ochilgan (decompressed) matnning IKKALASIDA HAM xavfli PDF
     tuzilma belgilarini (/JavaScript, /OpenAction, /Launch, /AA,
     /EmbeddedFile, /RichMedia, /XFA) qidiradi.
  3. `/URI(...)` harakatlaridan VA matn ichidan (JS string'lar va h.k.)
     topilgan barcha URL'larni `threat_intel/url_intel.py`ning
     `analyze_url()` orqali o'tkazadi - bu PDF ichidagi fishing
     havolasini ham aniqlash imkonini beradi (foydalanuvchi buni
     "eng foydali qism" deb alohida ta'kidlagan edi).

ATAYLAB QILINMAGAN (halol cheklov): to'liq PDF obyekt grafigini
(xref/object stream) qurish - faqat matn-asosidagi qidiruv. Bu
JBIG2/LZW kabi kamdan-kam kodlashlarni yoki chuqur ichma-ich
siqilishlarni o'tkazib yuborishi mumkin, lekin xavfsizlik nuqtai
nazaridan eng muhim, keng tarqalgan hujum yo'llarini (FlateDecode
bilan siqilgan JS/OpenAction) qamrab oladi.
"""
import re
import zlib
from typing import Optional

from threat_intel.url_intel import analyze_url

PDF_EXTENSIONS = {"pdf"}

# zlib-bomb himoyasi (archive_scanner.py'dagi zip-bomb himoyasi bilan bir xil naqsh)
MAX_STREAM_COMPRESSED_SIZE = 5 * 1024 * 1024          # 5 MB'dan katta siqilgan stream o'qilmaydi
MAX_DECOMPRESSED_SIZE_PER_STREAM = 20 * 1024 * 1024   # bitta stream uchun 20 MB'dan ko'p ochilmaydi
MAX_TOTAL_DECOMPRESSED = 50 * 1024 * 1024             # butun fayl uchun jami 50 MB
MAX_URLS_ANALYZED = 20                                # fayl ichida juda ko'p URL bo'lsa, faqat birinchi 20 tasi tahlil qilinadi

_STREAM_RE = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)
_URI_RE = re.compile(rb"/URI\s*\(([^)]*)\)")
_URL_RE = re.compile(rb"https?://[^\s()<>\"'\\]+")

_MARKER_PATTERNS = {
    "JavaScript": re.compile(rb"/JavaScript|/JS\b"),
    "OpenAction": re.compile(rb"/OpenAction"),
    "Launch": re.compile(rb"/Launch"),
    "EmbeddedFile": re.compile(rb"/EmbeddedFile"),
    "AdditionalActions": re.compile(rb"/AA\b"),
    "RichMedia": re.compile(rb"/RichMedia"),
    "XFA": re.compile(rb"/XFA"),
}


def _decompress_streams(content: bytes) -> bytes:
    """PDF'dagi FlateDecode stream'larni ochib, hammasini bitta matn
    sifatida qaytaradi (marker/URL qidiruvi uchun) - xavfsizlik
    chegaralari bilan. Flate bo'lmagan (masalan xom rasm) stream'lar
    xato bilan o'tkazib yuboriladi - bu KUTILGAN, xato emas."""
    pieces = []
    total = 0
    for match in _STREAM_RE.finditer(content):
        if total >= MAX_TOTAL_DECOMPRESSED:
            break
        raw = match.group(1)
        if len(raw) > MAX_STREAM_COMPRESSED_SIZE:
            continue
        try:
            decompressor = zlib.decompressobj()
            out = decompressor.decompress(raw, MAX_DECOMPRESSED_SIZE_PER_STREAM)
        except zlib.error:
            continue
        if out:
            pieces.append(out)
            total += len(out)
    return b"\n".join(pieces)


def scan_pdf_file(filepath: str) -> Optional[dict]:
    """
    PDF faylini tekshiradi.

    Qaytaradi:
        None - fayl PDF emas yoki o'qib bo'lmadi
        {"suspicious": bool, "findings": [str, ...], "urls": [str, ...]}
    """
    ext = filepath.rsplit(".", 1)[-1].lower() if "." in filepath else ""
    if ext not in PDF_EXTENSIONS:
        return None

    try:
        with open(filepath, "rb") as f:
            content = f.read()
    except OSError:
        return None

    if not content.startswith(b"%PDF"):
        return None

    decompressed = _decompress_streams(content)
    combined = content + b"\n" + decompressed

    found = {name: bool(pattern.search(combined)) for name, pattern in _MARKER_PATTERNS.items()}

    findings = []
    suspicious = False

    for name, present in found.items():
        if present:
            findings.append(f"PDF strukturasi: {name} topildi")

    # Avtomatik ishga tushirish (/Launch) - tashqi dasturni ishga
    # tushirish, PDF kontekstida deyarli HECH QACHON qonuniy emas.
    if found["Launch"]:
        findings.append("XAVFLI: /Launch (tashqi dastur/fayl ochish harakati)")
        suspicious = True

    # JavaScript + avtomatik trigger (OpenAction yoki Additional Actions) -
    # klassik "PDF ochilishi bilan zararli JS ishga tushadi" naqshi.
    if found["JavaScript"] and (found["OpenAction"] or found["AdditionalActions"]):
        findings.append("XAVFLI KOMBINATSIYA: JavaScript + avtomatik ishga tushirish harakati (OpenAction/AA)")
        suspicious = True

    # --- URL ekstraktsiyasi va tahlili (threat_intel/url_intel.py orqali) ---
    urls = set()
    for m in _URI_RE.finditer(combined):
        try:
            urls.add(m.group(1).decode("utf-8", errors="replace"))
        except Exception:
            pass
    for m in _URL_RE.finditer(combined):
        try:
            urls.add(m.group(0).decode("utf-8", errors="replace"))
        except Exception:
            pass

    for url in sorted(urls)[:MAX_URLS_ANALYZED]:
        analysis = analyze_url(url)
        if analysis["level"] in ("malicious", "high") or analysis["is_punycode"] or analysis["has_userinfo_trick"]:
            findings.append(
                f"Shubhali URL (PDF ichida): {url} - daraja={analysis['level']}, ball={analysis['score']}"
            )
            suspicious = True

    return {"suspicious": suspicious, "findings": findings, "urls": sorted(urls)}
