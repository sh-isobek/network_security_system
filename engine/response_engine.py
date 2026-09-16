"""
Response Engine - 5-bosqich.

`alerts` jadvalidan hali avtomatik tarmoq chorasi ko'rilmagan
(`network_response_done=False`) yozuvlarni oladi, tegishli qurilmani
(device_id orqali) topadi va adapter_registry orqali mos bloklash/
karantin adapterini chaqiradi. Natija `alert.action_taken`ga QO'SHIB
yoziladi (ustidan YOZILMAYDI) - shunda boshqa engine (masalan Endpoint
Agent'ning "fayl o'chirildi" xabari) allaqachon yozgan fayl-darajasidagi
xabar yo'qolib qolmaydi.

Faqat severity="high" yoki "critical" bo'lgan alertlar avtomatik chora
ko'radi (past darajadagilar faqat administratorga xabar beriladi -
7-bosqich) - lekin BARCHA alert baribir `network_response_done=True`
qilib belgilanadi (aks holda past darajali alertlar HAR TSIKLDA qayta-
qayta ko'rib chiqilaverardi).

MUHIM (o'zi topilgan real bug, tuzatildi): ilgari bu yerda `alerts`
jadvalidan `action_taken.like("TODO%")` MATN QIDIRUVI orqali "navbatdagi"
yozuvlar topilardi. Lekin `file_analysis_engine.py`/`deep_scan_engine.py`/
`api/server.py::report_incident()` - hech biri "TODO" bilan BOSHLANMAYDIGAN
matn yozardi (masalan "TASDIQLANGAN: ...izolyatsiyasi navbatda" - matnda
"navbatda" deyilsa-da, "TODO" bilan boshlanmagani uchun HECH QACHON
haqiqatan navbatga tushmasdi) - natijada virus aniqlanganda qurilma
avtomatik ravishda TARMOQDAN UZILMASDI, faqat DNS/connection blacklist
orqali aniqlangan tahdidlar (parser_engine.py, "TODO"dan foydalangan)
avtomatik bloklanardi. Bu xato hech qachon sinalmagan edi, chunki avvalgi
test o'zi qo'lda "TODO: ..." bilan sintetik alert yaratardi - haqiqiy
`file_analysis_engine`/`report_incident` kod yo'lini emas.

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

from sqlalchemy import or_

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


def _append_action(alert: Alert, text: str):
    """Mavjud action_taken matniga QO'SHIB yozadi - ustidan yozmaydi
    (masalan Endpoint Agent'ning "fayl o'chirildi" xabari saqlanib qoladi)."""
    existing = (alert.action_taken or "").rstrip()
    alert.action_taken = f"{existing} | {text}" if existing else text


def respond_one(session, alert: Alert):
    alert.network_response_done = True

    if alert.severity not in AUTO_RESPONSE_SEVERITIES:
        _append_action(alert, f"Avtomatik tarmoq chorasi ko'rilmadi (severity={alert.severity})")
        return

    if not alert.device_id:
        _append_action(alert, "Qurilma aniqlanmadi - avtomatik tarmoq chorasi ko'rib bo'lmadi, qo'lda tekshirish kerak")
        logger.warning(f"Alert {alert.id}: device_id yo'q, tarmoq chorasi ko'rilmadi")
        return

    device = session.query(Device).filter(Device.id == alert.device_id).first()
    if device is None:
        _append_action(alert, "Qurilma bazada topilmadi - avtomatik tarmoq chorasi ko'rib bo'lmadi")
        return

    target = _device_to_target(device)
    result = quarantine_device(target)

    if result.success:
        _append_action(alert, f"AVTOMATIK TARMOQ CHORASI: {result.message} (adapter: {result.adapter_name})")
        logger.warning(f"Alert {alert.id}: {device.ip_address} tarmoqdan izolyatsiya qilindi ({result.adapter_name})")
    else:
        _append_action(alert, f"TARMOQ CHORASI MUVAFFAQIYATSIZ: {result.message} - qo'lda aralashuv kerak")
        logger.error(f"Alert {alert.id}: tarmoq chorasi muvaffaqiyatsiz - {result.message}")


def run_once():
    session = get_session()
    try:
        pending = (
            session.query(Alert)
            .filter(or_(Alert.network_response_done.is_(None), Alert.network_response_done.is_(False)))
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
