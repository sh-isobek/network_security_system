"""
Parser Engine - 1-bosqichning yuragi.

Vazifasi:
  1. `raw_logs` jadvalidan processed=False bo'lgan yozuvlarni oladi.
  2. Ro'yxatdagi har bir parser'ni ('can_parse') sinab ko'radi, mos kelgani
     bilan xabarni structured ma'lumotga aylantiradi.
  3. Natijaga qarab:
       - DHCP lease bo'lsa -> devices jadvalini yangilaydi (IP/MAC/hostname)
       - connection/dns_query bo'lsa -> events jadvaliga yozadi,
         devices jadvalidagi last_seen'ni yangilaydi
       - agar dns_query bo'lib, domen blacklist'da bo'lsa -> alerts
         jadvaliga yozuv qo'shadi (bloklash 5-bosqichda ulanadi)
  4. Yozuvni processed=True qilib belgilaydi.

Ishga tushirish (doimiy tsikl sifatida, masalan systemd/cron orqali):
    python -m engine.parser_engine --loop
Yoki bir martalik ishga tushirish (mavjud navbatni tozalash):
    python -m engine.parser_engine
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import RawLog, Device, Event, WebAccessLog, Alert, WhitelistEntry, BlacklistEntry, utcnow
from parsers.kerio_parser import KerioConnectionParser, KerioDHCPParser
from parsers.windows_dns_parser import WindowsDNSParser

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("parser_engine")

# Yangi manba qo'shilsa, shu ro'yxatga bitta qator qo'shish kifoya
PARSERS = [
    KerioDHCPParser(),
    KerioConnectionParser(),
    WindowsDNSParser(),
]

BATCH_SIZE = 200


def _is_whitelisted(session, value: str) -> bool:
    if not value:
        return False
    return session.query(WhitelistEntry).filter(WhitelistEntry.value == value).first() is not None


def _is_blacklisted(session, value: str):
    if not value:
        return None
    return session.query(BlacklistEntry).filter(BlacklistEntry.value == value).first()


def _upsert_device(session, ip: str, mac: str = None, hostname: str = None, source: str = "unknown"):
    device = session.query(Device).filter(Device.ip_address == ip).first()
    if device is None:
        device = Device(ip_address=ip, mac_address=mac, hostname=hostname, source=source)
        session.add(device)
        session.flush()  # id olish uchun
    else:
        if mac:
            device.mac_address = mac
        if hostname:
            device.hostname = hostname
        device.last_seen = utcnow()
    return device


def process_one(session, raw_log: RawLog):
    parsed = None
    used_parser = None
    for parser in PARSERS:
        try:
            if parser.can_parse(raw_log.raw_message):
                parsed = parser.parse(raw_log.raw_message)
                if parsed:
                    used_parser = parser.name
                    break
        except Exception as exc:
            logger.warning(f"{parser.name} xatolik berdi: {exc}")

    if parsed is None:
        # Hech qaysi parser tanimadi - keyinchalik tahlil uchun processed=True
        # qilib qo'yamiz, lekin "unparsed" deb belgilashimiz ham mumkin edi.
        raw_log.processed = True
        return

    event_type = parsed.get("event_type")

    if event_type == "dhcp_lease":
        _upsert_device(
            session,
            ip=parsed["source_ip"],
            mac=parsed.get("mac_address"),
            hostname=parsed.get("hostname"),
            source="kerio_dhcp",
        )
        raw_log.processed = True
        return

    # connection yoki dns_query
    device = _upsert_device(session, ip=parsed["source_ip"], source=used_parser)

    event = Event(
        device_id=device.id,
        source_ip=parsed["source_ip"],
        dest_ip=parsed.get("dest_ip"),
        dest_domain=parsed.get("dest_domain"),
        dest_port=parsed.get("dest_port"),
        protocol=parsed.get("protocol"),
        raw_log_id=raw_log.id,
    )
    session.add(event)
    session.flush()

    # DNS query ham sayt/domen faoliyati sifatida alohida indekslanadi.
    # Bu Zeek HTTP/TLS yo'q bo'lgan tarmoqlarda ham dashboard orqali
    # "qaysi IP qaysi domenni qachon so'ragan" qidiruvini beradi.
    if event_type == "dns_query" and parsed.get("dest_domain"):
        session.add(WebAccessLog(
            timestamp=event.timestamp, device_id=device.id,
            source_ip=parsed["source_ip"], dest_ip=parsed.get("dest_ip"),
            domain=str(parsed["dest_domain"]).rstrip(".").lower(),
            url=f"dns://{str(parsed['dest_domain']).rstrip('.').lower()}",
            protocol="DNS", source=used_parser or "dns",
        ))

    if event_type == "dns_query":
        target = parsed.get("dest_domain")
        if _is_whitelisted(session, target):
            logger.debug(f"Whitelist: {target} - o'tkazib yuborildi")
        else:
            bl_hit = _is_blacklisted(session, target)
            if bl_hit:
                alert = Alert(
                    event_id=event.id,
                    device_id=device.id,
                    severity="high",
                    reason=f"Blacklist'dagi domenga so'rov: {target} (manba: {bl_hit.source})",
                    action_taken="TODO: bloklash backend hali ulanmagan (5-bosqich)",
                    notified=False,
                )
                session.add(alert)
                logger.warning(f"ALERT: {parsed['source_ip']} -> {target} (blacklist)")

    raw_log.processed = True


def run_once(session=None):
    own_session = session is None
    session = session or get_session()
    try:
        pending = (
            session.query(RawLog)
            .filter(RawLog.processed == False)  # noqa: E712
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0
        for raw_log in pending:
            process_one(session, raw_log)
        session.commit()
        logger.info(f"{len(pending)} ta yozuv qayta ishlandi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        if own_session:
            session.close()


def run_loop(interval_seconds: int = 5):
    logger.info("Parser engine tsiklda ishga tushdi (Ctrl+C to'xtatish)")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="Doimiy tsiklda ishlash")
    ap.add_argument("--interval", type=int, default=5, help="Tsikl oralig'i (soniya)")
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        count = run_once()
        logger.info(f"Bir martalik ishga tushirish yakunlandi: {count} ta yozuv")
