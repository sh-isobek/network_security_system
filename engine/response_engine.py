"""
Response Engine - 5-bosqich.

`alerts` jadvalidan hali chora ko'rilmagan (action_taken="TODO..." bilan
boshlanadigan) yozuvlarni oladi, tegishli qurilmani (device_id orqali)
topadi va adapter_registry orqali mos bloklash/karantin adapterini
chaqiradi. Natijaga qarab alert.action_taken yangilanadi.

Faqat severity="high" yoki "critical" bo'lgan alertlar avtomatik chora
ko'radi (past darajadagilar faqat administratorga xabar beriladi -
7-bosqich).

Ishga tushirish:
    python -m engine.response_engine
    python -m engine.response_engine --loop
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
from response.base_adapter import TargetDevice
from response.adapter_registry import quarantine_device

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("response_engine")

BATCH_SIZE = 50
AUTO_RESPONSE_SEVERITIES = {"high", "critical"}


def _device_to_target(device: Device) -> TargetDevice:
    return TargetDevice(
        ip_address=device.ip_address,
        mac_address=device.mac_address,
        connection_type=device.connection_type,
        switch_port=None,  # keyinchalik CAM-table orqali avtomatik aniqlanadi
    )


def respond_one(session, alert: Alert):
    if alert.severity not in AUTO_RESPONSE_SEVERITIES:
        alert.action_taken = f"Avtomatik chora ko'rilmadi (severity={alert.severity}) - faqat xabarnoma yuboriladi"
        return

    if not alert.device_id:
        alert.action_taken = "Qurilma aniqlanmadi - avtomatik chora ko'rib bo'lmadi, qo'lda tekshirish kerak"
        logger.warning(f"Alert {alert.id}: device_id yo'q, chora ko'rilmadi")
        return

    device = session.query(Device).filter(Device.id == alert.device_id).first()
    if device is None:
        alert.action_taken = "Qurilma bazada topilmadi - avtomatik chora ko'rib bo'lmadi"
        return

    target = _device_to_target(device)
    result = quarantine_device(target)

    if result.success:
        alert.action_taken = f"AVTOMATIK CHORA: {result.message} (adapter: {result.adapter_name})"
        logger.warning(f"Alert {alert.id}: {device.ip_address} karantinga o'tkazildi ({result.adapter_name})")
    else:
        alert.action_taken = f"CHORA MUVAFFAQIYATSIZ: {result.message} - qo'lda aralashuv kerak"
        logger.error(f"Alert {alert.id}: chora muvaffaqiyatsiz - {result.message}")


def run_once():
    session = get_session()
    try:
        pending = (
            session.query(Alert)
            .filter(Alert.action_taken.like("TODO%"))
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0
        for alert in pending:
            respond_one(session, alert)
        session.commit()
        logger.info(f"{len(pending)} ta alert uchun javob chorasi ko'rildi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = 5):
    logger.info("Response engine tsiklda ishga tushdi")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=5)
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        logger.info(f"Yakunlandi: {n} ta alert qayta ishlandi")
