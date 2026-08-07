"""
Queue Ingest Worker - yangi TZ 17 va 21-bo'limlar (Queue + Horizontal Scaling).

`raw_syslog_queue`dan xabarlarni o'qib, `raw_logs` jadvaliga yozadi -
xuddi `collectors/syslog_server.py` to'g'ridan-to'g'ri qilgani kabi,
lekin bu yerda alohida, mustaqil jarayonda amalga oshiriladi.

GORIZONTAL MIQYOSLANISH: bu worker'ni bir vaqtda bir nechta nusxada
ishga tushirish mumkin (masalan `docker compose up --scale
queue_ingest_worker=5`) - RabbitMQ xabarlarni worker'lar orasida
avtomatik taqsimlaydi (round-robin), bir xil xabar ikki marta qayta
ishlanmaydi (RabbitMQ'ning o'z kafolat mexanizmi orqali - `basic_ack`).

Ishga tushirish:
    python -m engine.queue_ingest_worker --loop
    python -m engine.queue_ingest_worker --once   # test uchun, bitta batch
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import RawLog
from messaging.rabbitmq_client import consume_batch

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("queue_ingest_worker")

RAW_SYSLOG_QUEUE = os.getenv("RAW_SYSLOG_QUEUE", "raw_syslog_queue")


def _handle_message(data: dict):
    """Bitta navbat xabarini bazaga yozadi. Xatolik bo'lsa exception
    ko'taradi - shunda rabbitmq_client.consume_batch xabarni navbatga
    qaytaradi (requeue), yo'qotilmaydi."""
    session = get_session()
    try:
        entry = RawLog(source_ip=data["source_ip"], raw_message=data["raw_message"])
        session.add(entry)
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_once(max_messages: int = 200, timeout_seconds: float = 5.0) -> int:
    return consume_batch(RAW_SYSLOG_QUEUE, _handle_message, max_messages=max_messages, timeout_seconds=timeout_seconds)


def run_loop(timeout_seconds: float = 5.0):
    logger.info(f"Queue ingest worker tsiklda ishga tushdi (navbat: {RAW_SYSLOG_QUEUE})")
    while True:
        try:
            n = run_once(timeout_seconds=timeout_seconds)
            if n > 0:
                logger.info(f"{n} ta xabar qayta ishlandi")
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
            time.sleep(2)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--once", action="store_true")
    args = ap.parse_args()

    if args.loop:
        run_loop()
    else:
        n = run_once()
        logger.info(f"Yakunlandi: {n} ta xabar qayta ishlandi")
