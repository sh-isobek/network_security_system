"""
Suricata eve.json Reader - 2-bosqich.

Suricata `eve.json`ga JSON Lines formatida yozadi (har qatorda bitta
hodisa). Bu modul faylni "tail -f" uslubida kuzatib boradi va faqat
`"event_type": "fileinfo"` yozuvlarini oladi (fayl transferlari haqida
- boshqa event turlari, masalan flow/dns, bu bosqichda kerak emas,
chunki DNS allaqachon alohida Windows DNS parser orqali qamrab olingan).

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
        checked=False,
    )
    session.add(entry)
    logger.info(f"Fayl aniqlandi: {filename} ({sha256[:12]}...) {event.get('src_ip')} -> {event.get('dest_ip')}")
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
