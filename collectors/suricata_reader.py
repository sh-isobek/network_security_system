"""
Suricata eve.json Reader - 2-bosqich.

Suricata `eve.json`ga JSON Lines formatida yozadi (har qatorda bitta
hodisa). Bu modul faylni "tail -f" uslubida kuzatib boradi va faqat
`"event_type": "fileinfo"` yozuvlarini oladi (fayl transferlari haqida
- boshqa event turlari, masalan flow/dns, bu bosqichda kerak emas,
chunki DNS allaqachon alohida Windows DNS parser orqali qamrab olingan).

MUHIM (real arxitektura bo'shlig'i tuzatilgan - foydalanuvchining
chuqur tahlilidagi ②-band): avval `FileEvent.stored_path` HECH QACHON
to'ldirilmasdi - `engine/deep_scan_engine.py` (YARA/ClamAV/Office/
Archive) FAQAT `stored_path` mavjud bo'lganda ishlay oladi, shuning
uchun Suricata orqali kelgan fayllar uchun bu tekshiruvlarning
BARCHASI jimgina o'tkazib yuborilardi - faqat hash (VT/MalwareBazaar/
local blacklist) natijasiga tayanilardi. Endi `fileinfo.stored`
(Suricata bu faylni HAQIQATAN diskka saqladimi - `file-store` qoidasi
mos kelgan bo'lsa) `true` bo'lsa, `stored_path` `SURICATA_FILESTORE_
DIR` (standart: `/var/log/suricata/files`, `docs_SURICATA_SETUP.md`
bilan bir xil) + SHA256 sifatida hisoblab qo'yiladi - bu Suricata
`file-store: version: 2` sozlamasining HAQIQIY fayl nomlash
konvensiyasi (rasmiy hujjatlarga muvofiq: fayl to'g'ridan-to'g'ri
`<dir>/<sha256>` sifatida, ichki papkalarsiz saqlanadi). Eski
`file-store: version: 1` (endi eskirgan) boshqa, ichma-ich papka
konvensiyasidan foydalanadi - bu yerda QO'LLAB-QUVVATLANMAYDI (`docs_
SURICATA_SETUP.md` `version: 2`ni talab qiladi).

Bu modul o'zi (`suricata_reader`, docker-compose'da eve.json'ni
o'qiydigan xizmat) `/var/log/suricata/files` papkasiga ULANMAGAN -
faqat YO'L QATORINI yozadi. Haqiqiy faylni KEYINROQ `deep_scan_engine`
xizmati (o'sha papka unga bog'langan) ochib tekshiradi - ikkalasi ham
bir xil host katalogini bir xil konteyner yo'liga bog'lagani uchun
yo'l qatori ikkalasida ham bir xil ma'noga ega bo'ladi.

Ishga tushirish:
    python -m collectors.suricata_reader --file /var/log/suricata/eve.json
"""
import argparse
import json
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import FileEvent

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("suricata_reader")


def _guess_channel(filename: str, dest_ip: str = None) -> str:
    """Fayl manbasini (Telegram/Email/Web) taxminiy aniqlash - keyingi
    bosqichlarda HTTP header/SNI asosida aniqroq qilinadi."""
    if not filename:
        return "unknown"
    lower = filename.lower()
    if "telegram" in lower:
        return "telegram"
    return "web"


def process_fileinfo_event(session, event: dict) -> bool:
    """Bitta Suricata fileinfo JSON yozuvini file_events jadvaliga yozadi.
    Qaytaradi: True - yangi yozuv qo'shildi, False - o'tkazib yuborildi
    (hash yo'q yoki takroriy)."""
    fileinfo = event.get("fileinfo", {})
    sha256 = fileinfo.get("sha256")
    if not sha256:
        return False  # hash hisoblanmagan fayl - o'tkazib yuboramiz

    # Bir xil hash+src_ip juftligi qayta yozilmasligi uchun oddiy tekshiruv
    exists = (
        session.query(FileEvent)
        .filter(FileEvent.sha256 == sha256, FileEvent.src_ip == event.get("src_ip"))
        .first()
    )
    if exists:
        return False

    filename = fileinfo.get("filename", "")
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else None

    # MUHIM (real arxitektura bo'shlig'i tuzatilgan): `fileinfo.stored`
    # FAQAT bu aniq fayl `filestore;` qoidasiga mos kelib, HAQIQATAN
    # diskka yozilganda `true` bo'ladi - `force-hash` orqali hash HAR
    # BIR ko'rilgan fayl uchun hisoblanadi, lekin bu ularning BARCHASI
    # saqlangani degani EMAS. `stored=false`/yo'q bo'lsa, `stored_path`
    # bo'sh qoldiriladi (aks holda mavjud bo'lmagan faylga yo'l
    # ko'rsatib qo'yamiz - `deep_scan_engine.py` buni baribir xavfsiz
    # o'tkazib yuboradi, lekin noto'g'ri bo'lardi).
    stored_path = None
    if fileinfo.get("stored"):
        filestore_dir = os.getenv("SURICATA_FILESTORE_DIR", "/var/log/suricata/files")
        stored_path = os.path.join(filestore_dir, sha256)

    entry = FileEvent(
        src_ip=event.get("src_ip"),
        dest_ip=event.get("dest_ip"),
        filename=filename,
        file_ext=file_ext,
        magic=fileinfo.get("magic"),
        size=fileinfo.get("size"),
        sha256=sha256,
        md5=fileinfo.get("md5"),
        protocol=event.get("proto") or event.get("app_proto"),
        channel=_guess_channel(filename),
        stored_path=stored_path,
        checked=False,
    )
    session.add(entry)
    stored_note = " [file-store'da saqlangan]" if stored_path else " [faqat hash - fayl saqlanmagan]"
    logger.info(f"Fayl aniqlandi: {filename} ({sha256[:12]}...) {event.get('src_ip')} -> {event.get('dest_ip')}{stored_note}")
    return True


def read_existing(filepath: str):
    """Fayldagi mavjud barcha qatorlarni bir martalik o'qiydi (test/backlog uchun)."""
    session = get_session()
    count = 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "fileinfo":
                    if process_fileinfo_event(session, event):
                        count += 1
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    return count


def follow_file(filepath: str, interval: float = 1.0):
    """eve.json faylini tail -f uslubida doimiy kuzatadi."""
    logger.info(f"eve.json kuzatilmoqda: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)  # faylning oxiridan boshlaymiz
        while True:
            line = f.readline()
            if not line:
                time.sleep(interval)
                continue
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") == "fileinfo":
                session = get_session()
                try:
                    process_fileinfo_event(session, event)
                    session.commit()
                except Exception as exc:
                    session.rollback()
                    logger.error(f"Xatolik: {exc}")
                finally:
                    session.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="/var/log/suricata/eve.json")
    ap.add_argument("--once", action="store_true", help="Mavjud faylni bir marta o'qib chiqish (test uchun)")
    args = ap.parse_args()

    if args.once:
        n = read_existing(args.file)
        logger.info(f"{n} ta fileinfo yozuvi qayta ishlandi")
    else:
        follow_file(args.file)
