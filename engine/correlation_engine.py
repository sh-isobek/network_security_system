"""
Correlation Engine - alohida Alert'larni bitta Incident'ga birlashtiradi.

`alerts` jadvalidan hali hech qanday Incident'ga bog'lanmagan
(`incident_id IS NULL`) yozuvlarni oladi. Har bir alert uchun: agar
o'sha QURILMADA `CORRELATION_WINDOW_MINUTES` ichida oxirgi marta
faollik ko'rsatgan OCHIQ (`status="open"`) Incident bo'lsa, alert
o'sha Incident'ga qo'shiladi (oynani "yangilaydi" - Incident davom
etayotgan hujum zanjiri sifatida cho'zilaveradi). Aks holda, YANGI
Incident yaratiladi.

Bu ATAYLAB ODDIY, boshlang'ich versiya: faqat BITTA qurilma doirasida,
vaqt-oynasi bo'yicha guruhlash. Qurilmalar orasidagi (lateral movement)
yoki qoida-asosidagi (Detection Rule) korrelyatsiya - alohida, keyingi
bosqich.

Ishga tushirish:
    python -m engine.correlation_engine
    python -m engine.correlation_engine --loop
"""
import argparse
import logging
import os
import sys
import time
from datetime import timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL, CORRELATION_WINDOW_MINUTES
from db.database import get_session
from db.models import Alert, Incident, Device

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("correlation_engine")

BATCH_SIZE = 200

# Severity darajalarini solishtirish uchun (Incident guruhdagi ENG
# YUQORI severity'ni ko'rsatishi kerak - masalan bitta "low" va bitta
# "critical" alert bir xil Incident'ga tushsa, Incident "critical"
# bo'lib qolishi kerak).
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _severity_rank(severity) -> int:
    return SEVERITY_RANK.get((severity or "").lower(), 0)


def _incident_title(device: Device, alert: Alert) -> str:
    who = (device.hostname if device and device.hostname else None) or (device.ip_address if device else "noma'lum qurilma")
    reason = (alert.reason or "").strip().splitlines()[0] if alert.reason else "aniqlanmagan tahdid"
    if len(reason) > 120:
        reason = reason[:117] + "..."
    return f"{who}: {reason}"


def correlate_one(session, alert: Alert) -> Incident:
    """Bitta alertni mavjud Incident'ga qo'shadi yoki yangisini yaratadi."""
    window_start = alert.timestamp - timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    existing = None
    if alert.device_id is not None:
        existing = (
            session.query(Incident)
            .filter(
                Incident.device_id == alert.device_id,
                Incident.status == "open",
                Incident.last_seen >= window_start,
            )
            .order_by(Incident.last_seen.desc())
            .first()
        )

    if existing:
        existing.alert_count += 1
        existing.last_seen = max(existing.last_seen, alert.timestamp)
        existing.first_seen = min(existing.first_seen, alert.timestamp)
        if _severity_rank(alert.severity) > _severity_rank(existing.severity):
            existing.severity = alert.severity
        alert.incident_id = existing.id
        return existing

    device = session.query(Device).filter(Device.id == alert.device_id).first() if alert.device_id else None
    incident = Incident(
        title=_incident_title(device, alert),
        severity=alert.severity or "low",
        status="open",
        device_id=alert.device_id,
        alert_count=1,
        first_seen=alert.timestamp,
        last_seen=alert.timestamp,
    )
    session.add(incident)
    session.flush()  # incident.id kerak, alert.incident_id o'rnatishdan oldin
    alert.incident_id = incident.id
    return incident


def run_once():
    session = get_session()
    try:
        pending = (
            session.query(Alert)
            .filter(Alert.incident_id.is_(None))
            .order_by(Alert.timestamp.asc())
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0

        for alert in pending:
            correlate_one(session, alert)

        session.commit()
        logger.info(f"{len(pending)} ta alert Incident'larga birlashtirildi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = 15):
    logger.info(f"Correlation engine tsiklda ishga tushdi (oyna: {CORRELATION_WINDOW_MINUTES} daqiqa)")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=15)
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        logger.info(f"Yakunlandi: {n} ta alert birlashtirildi")
