"""
Notification Engine - 7-bosqich.

`alerts` jadvalidan notified=False bo'lgan yozuvlarni oladi, tegishli
qurilma ma'lumotlarini (device_id orqali) to'plab, Email va/yoki
Telegram orqali yuboradi. Muvaffaqiyatli yuborilgandan keyin
notified=True qilib belgilaydi.

Qaysi kanal(lar) ishlatilishi NOTIFY_CHANNELS orqali sozlanadi
(.env: NOTIFY_CHANNELS=email,telegram yoki faqat bittasi).

Ishga tushirish:
    python -m engine.notification_engine
    python -m engine.notification_engine --loop
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import Alert, Device
from notifications.email_notifier import send_alert_email
from notifications.telegram_notifier import send_alert_telegram

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("notification_engine")

BATCH_SIZE = 50
NOTIFY_CHANNELS = [c.strip() for c in os.getenv("NOTIFY_CHANNELS", "email,telegram").split(",") if c.strip()]


def _build_alert_data(session, alert: Alert) -> dict:
    device = session.query(Device).filter(Device.id == alert.device_id).first() if alert.device_id else None
    return {
        "timestamp": alert.timestamp.strftime("%Y-%m-%d %H:%M:%S") if alert.timestamp else "",
        "hostname": device.hostname if device and device.hostname else "Nomalum",
        "ip_address": device.ip_address if device else "Nomalum",
        "mac_address": device.mac_address if device and device.mac_address else "Nomalum",
        "connection_type": {"wifi": "Wi-Fi", "cable": "Kabel"}.get(
            device.connection_type if device else None, "Nomalum"
        ),
        "reason": alert.reason or "",
        "action_taken": alert.action_taken or "",
        "severity": alert.severity or "medium",
    }


def notify_one(session, alert: Alert) -> bool:
    """Bitta alert uchun barcha sozlangan kanallar orqali yuboradi.
    Kamida bitta kanal muvaffaqiyatli bo'lsa True qaytaradi."""
    alert_data = _build_alert_data(session, alert)
    any_success = False

    if "email" in NOTIFY_CHANNELS:
        if send_alert_email(alert_data):
            any_success = True

    if "telegram" in NOTIFY_CHANNELS:
        if send_alert_telegram(alert_data):
            any_success = True

    return any_success


def run_once():
    session = get_session()
    try:
        pending = (
            session.query(Alert)
            .filter(Alert.notified == False)  # noqa: E712
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0

        sent_count = 0
        for alert in pending:
            success = notify_one(session, alert)
            if success:
                alert.notified = True
                sent_count += 1
            else:
                logger.warning(f"Alert {alert.id}: hech qanday kanal orqali yuborilmadi, keyingi tsiklda qayta urinilb ko'riladi")

        session.commit()
        logger.info(f"{sent_count}/{len(pending)} ta alert muvaffaqiyatli xabar qilindi")
        return sent_count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = 10):
    logger.info(f"Notification engine tsiklda ishga tushdi (kanallar: {NOTIFY_CHANNELS})")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=10)
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        logger.info(f"Yakunlandi: {n} ta alert xabar qilindi")
