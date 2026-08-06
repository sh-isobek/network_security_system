"""
Snort Reader - Suricata'ga alternativ/qo'shimcha IDS integratsiyasi
(yangi TZ 8-bo'lim: "IDS/IPS: Suricata, Zeek, Snort").

Snort'ning `alert_fast` formatidagi log faylini o'qiydi. Namuna qator:

    08/06-08:39:01.972343  [**] [1:1000001:1] TEST Suspicious port 4444 (C2-like) [**] [Priority: 1] {TCP} 10.0.0.5:51234 -> 10.0.0.99:4444

Format: <vaqt>  [**] [gid:sid:rev] <xabar> [**] [Priority: N] {PROTO} SRC_IP:PORT -> DST_IP:PORT

MUHIM FARQ Suricata'dan: Suricata'da avval "fileinfo" event kelib,
keyin hash tekshiriladi (ko'p bosqichli tahlil). Snort'da esa alert -
bu allaqachon **yakuniy signal** (qoida ishga tushdi = xavfli deb
topildi), shuning uchun bu reader to'g'ridan-to'g'ri Alert yaratadi,
oraliq FileEvent bosqichisiz.

Priority -> severity moslashtirish (Snort standart qoidalar
konventsiyasiga ko'ra): 1=critical/high, 2=medium, 3=low.

Ishga tushirish:
    python -m collectors.snort_reader --file /tmp/snort_test/alert --once   # test uchun
    python -m collectors.snort_reader --file /var/log/snort/alert            # doimiy kuzatish
"""
import argparse
import logging
import os
import re
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import Device, Event, Alert

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("snort_reader")

# 08/06-08:39:01.972343  [**] [1:1000001:1] MSG [**] [Priority: 1] {TCP} SRC:PORT -> DST:PORT
_ALERT_RE = re.compile(
    r"^(?P<time>\S+)\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<msg>.+?)\s+\[\*\*\]\s+\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>\w+)\}\s+(?P<src_ip>[\d.]+):(?P<src_port>\d+)\s+->\s+"
    r"(?P<dst_ip>[\d.]+):(?P<dst_port>\d+)"
)

# Snort priority -> bizning severity darajamiz
PRIORITY_TO_SEVERITY = {1: "critical", 2: "high", 3: "medium", 4: "low"}


def parse_alert_line(line: str) -> dict | None:
    m = _ALERT_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    return {
        "sid": f"{d['gid']}:{d['sid']}:{d['rev']}",
        "message": d["msg"],
        "priority": int(d["priority"]),
        "protocol": d["proto"],
        "src_ip": d["src_ip"],
        "src_port": int(d["src_port"]),
        "dst_ip": d["dst_ip"],
        "dst_port": int(d["dst_port"]),
    }


def _upsert_device(session, ip: str) -> Device:
    device = session.query(Device).filter(Device.ip_address == ip).first()
    if device is None:
        device = Device(ip_address=ip, source="snort")
        session.add(device)
        session.flush()
    return device


def process_alert(session, parsed: dict):
    device = _upsert_device(session, parsed["src_ip"])

    event = Event(
        device_id=device.id,
        source_ip=parsed["src_ip"],
        dest_ip=parsed["dst_ip"],
        dest_port=parsed["dst_port"],
        protocol=parsed["protocol"],
    )
    session.add(event)
    session.flush()

    severity = PRIORITY_TO_SEVERITY.get(parsed["priority"], "medium")
    alert = Alert(
        event_id=event.id,
        device_id=device.id,
        severity=severity,
        reason=(
            f"Snort[{parsed['sid']}]: {parsed['message']} | "
            f"{parsed['src_ip']}:{parsed['src_port']} -> {parsed['dst_ip']}:{parsed['dst_port']}"
        ),
        action_taken="TODO: bloklash backend hali ulanmagan (5-bosqich)",
        notified=False,
    )
    session.add(alert)
    logger.warning(f"SNORT ALERT: {parsed['message']} ({parsed['src_ip']} -> {parsed['dst_ip']}:{parsed['dst_port']})")


def read_existing(filepath: str) -> int:
    """Fayldagi mavjud qatorlarni bir martalik o'qiydi (test/backlog uchun)."""
    session = get_session()
    count = 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parsed = parse_alert_line(line)
                if parsed:
                    process_alert(session, parsed)
                    count += 1
                else:
                    logger.debug(f"Mos kelmadi (o'tkazib yuborildi): {line[:80]}")
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    return count


def follow_file(filepath: str, interval: float = 1.0):
    """Snort alert faylini tail -f uslubida doimiy kuzatadi."""
    logger.info(f"Snort alert fayli kuzatilmoqda: {filepath}")
    with open(filepath, "r", encoding="utf-8") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(interval)
                continue
            parsed = parse_alert_line(line.strip())
            if parsed:
                session = get_session()
                try:
                    process_alert(session, parsed)
                    session.commit()
                except Exception as exc:
                    session.rollback()
                    logger.error(f"Xatolik: {exc}")
                finally:
                    session.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="/var/log/snort/alert")
    ap.add_argument("--once", action="store_true", help="Mavjud faylni bir marta o'qib chiqish (test uchun)")
    args = ap.parse_args()

    if args.once:
        n = read_existing(args.file)
        logger.info(f"{n} ta Snort alert qayta ishlandi")
    else:
        follow_file(args.file)
