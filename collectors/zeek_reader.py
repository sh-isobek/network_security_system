"""
Zeek Reader - Suricata/Snort'ga qo'shimcha tarmoq monitoring (yangi TZ
8-bo'lim). Zeek klassik "IDS" emas - u boy metadata log'lar generatsiya
qiluvchi tarmoq tahlil freymvorki (`conn.log`, `dns.log`, `http.log`,
`files.log`, `notice.log`).

MUHIM (halol cheklov): Zeek faqat OpenSUSE Build Service yoki Docker
Hub orqali tarqatiladi - bu loyiha tayyorlangan sandbox muhitida ikkala
domen ham tarmoq ruxsatlari ro'yxatida yo'q, manba kodidan build qilish
esa juda og'ir/uzoq. Shuning uchun bu integratsiya **haqiqiy Zeek
binary'siz**, lekin Zeek'ning rasmiy hujjatlashtirilgan JSON log
sxemasiga (https://docs.zeek.org) qat'iy mos yozilgan va sxemaga mos
sintetik ma'lumot bilan sinovdan o'tkazilgan.

Zeek sozlamasi (`local.zeek` ichida): `redef LogAscii::use_json = T;`
yoqilishi kerak - shunda har bir log fayl JSON Lines formatida yoziladi.

Qo'llab-quvvatlanadigan log turlari:
  - notice.log -> Alert (Zeek'ning o'z ichki alerting mexanizmi)
  - dns.log     -> Event (dns_query) + mavjud whitelist/blacklist tekshiruvi
  - conn.log    -> Event (connection)
  - files.log   -> FileEvent (Suricata fileinfo bilan bir xil pipeline -
                    hash allaqachon bor, file_analysis_engine avtomatik oladi)

Ishga tushirish:
    python -m collectors.zeek_reader --log-dir /opt/zeek/logs/current --once
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
from db.models import Device, Event, Alert, FileEvent, WebAccessLog, WhitelistEntry, BlacklistEntry, utcnow

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("zeek_reader")

# Zeek notice.log'dagi "note" maydoni -> bizning severity darajamiz.
# Zeek o'zi severity bermaydi (faqat "note" turi), shuning uchun eng
# keng tarqalgan tur nomlariga qarab moslashtiramiz - qolganlari uchun
# "medium" standart qiymat.
NOTICE_SEVERITY_MAP = {
    "Scan::Port_Scan": "medium",
    "Scan::Address_Scan": "medium",
    "Intel::Notice": "high",
    "SSL::Invalid_Server_Cert": "low",
    "Weird::Activity": "low",
    "HTTP::SQL_Injection_Attacker": "critical",
    "Trojan::Detected": "critical",
}


def _upsert_device(session, ip: str) -> Device:
    device = session.query(Device).filter(Device.ip_address == ip).first()
    if device is None:
        device = Device(ip_address=ip, source="zeek")
        session.add(device)
        session.flush()
    return device


def _is_whitelisted(session, value: str) -> bool:
    if not value:
        return False
    return session.query(WhitelistEntry).filter(WhitelistEntry.value == value).first() is not None


def _is_blacklisted(session, value: str):
    if not value:
        return None
    return session.query(BlacklistEntry).filter(BlacklistEntry.value == value).first()


def process_notice(session, rec: dict):
    """notice.log yozuvini Alert'ga aylantiradi (Zeek'ning o'z ichki alerting mexanizmi)."""
    src_ip = rec.get("src")
    if not src_ip:
        return
    device = _upsert_device(session, src_ip)

    note = rec.get("note", "Unknown")
    severity = NOTICE_SEVERITY_MAP.get(note, "medium")

    alert = Alert(
        device_id=device.id,
        severity=severity,
        reason=f"Zeek[{note}]: {rec.get('msg', '')} | src={src_ip} dst={rec.get('dst', '-')}",
        action_taken="TODO: bloklash backend hali ulanmagan (5-bosqich)",
        notified=False,
    )
    session.add(alert)
    logger.warning(f"ZEEK NOTICE: {note} - {rec.get('msg', '')} ({src_ip})")


def process_dns(session, rec: dict):
    """dns.log yozuvini Event'ga aylantiradi va blacklist tekshiradi (parser_engine bilan bir xil mantiq)."""
    src_ip = rec.get("id.orig_h")
    query = rec.get("query")
    if not src_ip or not query:
        return
    device = _upsert_device(session, src_ip)

    event = Event(
        device_id=device.id,
        source_ip=src_ip,
        dest_domain=query.rstrip("."),
        dest_port=53,
        protocol="DNS",
    )
    session.add(event)
    session.flush()

    session.add(WebAccessLog(
        timestamp=_zeek_timestamp(rec), device_id=device.id, source_ip=src_ip,
        dest_ip=rec.get("id.resp_h"), domain=query.rstrip(".").lower(),
        url=f"dns://{query.rstrip('.').lower()}", protocol="DNS", source="zeek_dns",
    ))

    if _is_whitelisted(session, query):
        return
    bl_hit = _is_blacklisted(session, query)
    if bl_hit:
        alert = Alert(
            event_id=event.id,
            device_id=device.id,
            severity="high",
            reason=f"Zeek DNS: Blacklist'dagi domenga so'rov: {query} (manba: {bl_hit.source})",
            action_taken="TODO: bloklash backend hali ulanmagan (5-bosqich)",
            notified=False,
        )
        session.add(alert)
        logger.warning(f"ZEEK DNS ALERT: {src_ip} -> {query} (blacklist)")


def process_conn(session, rec: dict):
    """conn.log yozuvini oddiy Event sifatida yozadi."""
    src_ip = rec.get("id.orig_h")
    dst_ip = rec.get("id.resp_h")
    if not src_ip:
        return
    device = _upsert_device(session, src_ip)

    event = Event(
        device_id=device.id,
        source_ip=src_ip,
        dest_ip=dst_ip,
        dest_port=rec.get("id.resp_p"),
        protocol=(rec.get("proto") or "").upper(),
    )
    session.add(event)


def process_file(session, rec: dict):
    """
    files.log yozuvini FileEvent sifatida yozadi - Suricata fileinfo bilan
    BIR XIL jadvalga (mavjud file_analysis_engine/deep_scan_engine buni
    avtomatik oladi, alohida kod yozish shart emas).
    """
    sha256 = rec.get("sha256")
    if not sha256:
        return  # Zeek md5/sha1 ham berishi mumkin, lekin bizning pipeline sha256 kutadi

    tx_hosts = rec.get("tx_hosts") or []
    rx_hosts = rec.get("rx_hosts") or []
    src_ip = tx_hosts[0] if tx_hosts else "0.0.0.0"
    dst_ip = rx_hosts[0] if rx_hosts else None

    exists = session.query(FileEvent).filter(FileEvent.sha256 == sha256, FileEvent.src_ip == src_ip).first()
    if exists:
        return

    filename = (rec.get("filename") or f"zeek_file_{rec.get('fuid', 'unknown')}")
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else None

    entry = FileEvent(
        src_ip=src_ip,
        dest_ip=dst_ip,
        filename=filename,
        file_ext=file_ext,
        magic=rec.get("mime_type"),
        size=rec.get("seen_bytes") or rec.get("total_bytes"),
        sha256=sha256,
        md5=rec.get("md5"),
        protocol=rec.get("source"),  # masalan "HTTP", "SMTP"
        channel="zeek",
        checked=False,
    )
    session.add(entry)
    logger.info(f"ZEEK FILE: {filename} ({sha256[:12]}...) {src_ip} -> {dst_ip}")


def _zeek_timestamp(rec: dict):
    """Zeek JSON `ts` (Unix epoch) -> naive UTC datetime."""
    import datetime as _dt
    value = rec.get("ts")
    if value is None:
        return utcnow()
    try:
        return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError, OverflowError):
        return utcnow()


def _normalise_domain(value):
    if not value:
        return None
    return str(value).strip().rstrip(".").lower() or None


def process_http(session, rec: dict):
    """Zeek http.log: HTTP uchun domen + to'liq URL/path tarixini saqlaydi."""
    src_ip = rec.get("id.orig_h")
    dst_ip = rec.get("id.resp_h")
    domain = _normalise_domain(rec.get("host"))
    if not src_ip or not domain:
        return

    device = _upsert_device(session, src_ip)
    method = (rec.get("method") or "GET").upper()
    path = rec.get("uri") or "/"
    # Absolute URI bo'lmasa, HTTP URL'ni host + path orqali tiklaymiz.
    url = path if str(path).startswith(("http://", "https://")) else f"http://{domain}{path}"
    status = rec.get("status_code")
    try:
        status = int(status) if status is not None else None
    except (TypeError, ValueError):
        status = None

    session.add(WebAccessLog(
        timestamp=_zeek_timestamp(rec), device_id=device.id, source_ip=src_ip,
        dest_ip=dst_ip, domain=domain, url=url, path=path, method=method,
        status_code=status, protocol="HTTP", user_agent=rec.get("user_agent"), source="zeek",
    ))


def process_ssl(session, rec: dict):
    """Zeek ssl.log: HTTPS uchun TLS SNI/domenni saqlaydi (URL path shifrlangani sabab ko'rinmaydi)."""
    src_ip = rec.get("id.orig_h")
    dst_ip = rec.get("id.resp_h")
    domain = _normalise_domain(rec.get("server_name"))
    if not src_ip or not domain:
        return

    device = _upsert_device(session, src_ip)
    session.add(WebAccessLog(
        timestamp=_zeek_timestamp(rec), device_id=device.id, source_ip=src_ip,
        dest_ip=dst_ip, domain=domain, url=f"https://{domain}/", path=None,
        method=None, status_code=None, protocol="HTTPS", user_agent=None, source="zeek_tls_sni",
    ))


_LOG_HANDLERS = {
    "notice.log": process_notice,
    "dns.log": process_dns,
    "http.log": process_http,
    "ssl.log": process_ssl,
    "conn.log": process_conn,
    "files.log": process_file,
}


def read_log_file(session, filepath: str, handler) -> int:
    count = 0
    with open(filepath, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # Zeek TSV formatida "#" bilan boshlanadigan sarlavha qatorlari bo'lishi mumkin
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            handler(session, rec)
            count += 1
    return count


def read_existing(log_dir: str) -> dict:
    """log_dir ichidagi barcha tanish log fayllarni bir martalik o'qiydi (test/backlog uchun)."""
    session = get_session()
    results = {}
    try:
        for filename, handler in _LOG_HANDLERS.items():
            filepath = os.path.join(log_dir, filename)
            if os.path.isfile(filepath):
                results[filename] = read_log_file(session, filepath, handler)
            else:
                results[filename] = 0
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    return results


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--log-dir", default="/opt/zeek/logs/current")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    if args.once:
        results = read_existing(args.log_dir)
        for filename, count in results.items():
            logger.info(f"{filename}: {count} ta yozuv qayta ishlandi")
    else:
        logger.error("Doimiy kuzatish rejimi (--loop) hali qo'shilmagan - --once bilan ishlating")
