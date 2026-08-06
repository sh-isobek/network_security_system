"""
Archive Scanner - ZIP arxivlarini xavfsiz tarzda ochib, ichidagi har bir
faylni yangi FileEvent sifatida bazaga qo'shadi (parent_file_event_id
orqali "qaysi arxivdan chiqqani" saqlanadi). Shundan so'ng bu yangi
yozuvlar oddiy pipeline (hash tekshiruv -> YARA -> makro/PDF) orqali
avtomatik qayta ishlanadi - alohida kod yozish shart emas.

RAR uchun: Python standart kutubxonasida RAR yozish qo'llab-quvvatlanmaydi
(litsenziya sababli). Production'da `unrar` CLI vositasi orqali (masalan
`rarfile` kutubxonasi + tizimda o'rnatilgan `unrar` binary) qo'shiladi.
Bu yerda faqat ZIP uchun to'liq ishlaydigan kod, RAR uchun skelet keltirilgan.

XAVFSIZLIK ESLATMASI (Zip Bomb / Path Traversal):
  - Har bir arxivda ochiladigan fayllar soni va umumiy hajmi cheklanadi
    (MAX_FILES, MAX_TOTAL_SIZE) - "zip bomb" hujumidan himoya.
  - Fayl nomlari tekshiriladi - "../" kabi path traversal urinishlari
    rad etiladi.
"""
import hashlib
import os
import sys
import zipfile
from typing import List

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.models import FileEvent

MAX_FILES = 200
MAX_TOTAL_SIZE = 500 * 1024 * 1024  # 500 MB
EXTRACT_DIR = "/tmp/archive_extraction"


def _safe_member_path(member_name: str) -> bool:
    """Path traversal ("../../etc/passwd" kabi) urinishlarini rad etadi."""
    normalized = os.path.normpath(member_name)
    return not normalized.startswith("..") and not os.path.isabs(normalized)


def extract_zip_and_queue(session, parent_fe: FileEvent) -> List[FileEvent]:
    """
    ZIP arxivini ochadi, ichidagi har bir fayl uchun yangi FileEvent
    yaratadi (checked=False - keyingi tsiklda hash orqali tekshiriladi).

    Qaytaradi: yaratilgan yangi FileEvent'lar ro'yxati.
    """
    if not parent_fe.stored_path or not os.path.isfile(parent_fe.stored_path):
        return []

    os.makedirs(EXTRACT_DIR, exist_ok=True)
    dest_dir = os.path.join(EXTRACT_DIR, str(parent_fe.id))
    os.makedirs(dest_dir, exist_ok=True)

    created = []
    total_size = 0

    try:
        with zipfile.ZipFile(parent_fe.stored_path) as zf:
            infolist = zf.infolist()

            if len(infolist) > MAX_FILES:
                parent_fe.deep_scan_findings = (parent_fe.deep_scan_findings or "") + \
                    f"\n[OGOHLANTIRISH] Arxivda {len(infolist)} ta fayl - zip-bomb shubhasi, faqat birinchi {MAX_FILES} tasi tekshirildi."
                infolist = infolist[:MAX_FILES]

            for member in infolist:
                if member.is_dir():
                    continue
                if not _safe_member_path(member.filename):
                    continue  # path traversal urinishi - o'tkazib yuborildi

                total_size += member.file_size
                if total_size > MAX_TOTAL_SIZE:
                    parent_fe.deep_scan_findings = (parent_fe.deep_scan_findings or "") + \
                        "\n[OGOHLANTIRISH] Arxiv umumiy hajmi limitdan oshdi - zip-bomb shubhasi."
                    break

                extracted_path = zf.extract(member, dest_dir)

                with open(extracted_path, "rb") as f:
                    content = f.read()
                sha256 = hashlib.sha256(content).hexdigest()
                md5 = hashlib.md5(content).hexdigest()
                ext = member.filename.rsplit(".", 1)[-1].lower() if "." in member.filename else None

                # Bir xil hash allaqachon mavjudmi - qayta yozmaslik
                exists = session.query(FileEvent).filter(FileEvent.sha256 == sha256).first()
                if exists:
                    continue

                child = FileEvent(
                    src_ip=parent_fe.src_ip,
                    dest_ip=parent_fe.dest_ip,
                    filename=member.filename,
                    file_ext=ext,
                    magic=None,
                    size=member.file_size,
                    sha256=sha256,
                    md5=md5,
                    protocol=parent_fe.protocol,
                    channel=parent_fe.channel,
                    checked=False,
                    stored_path=extracted_path,
                    parent_file_event_id=parent_fe.id,
                )
                session.add(child)
                session.flush()
                created.append(child)

    except zipfile.BadZipFile:
        parent_fe.deep_scan_findings = (parent_fe.deep_scan_findings or "") + "\n[XATO] ZIP fayli buzilgan yoki himoyalangan (parolli)."

    return created
