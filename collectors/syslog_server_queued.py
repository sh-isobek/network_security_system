"""
Navbat-asosli Syslog Collector - yangi TZ 17-bo'lim (Queue arxitekturasi).

`collectors/syslog_server.py`dan farqi: bu versiya kelgan UDP paketni
BAZAGA TO'G'RIDAN-TO'G'RI YOZMAYDI - RabbitMQ navbatiga joylaydi.
Alohida `engine/queue_ingest_worker.py` navbatdan o'qib, bazaga yozadi.

Nega bu muhim (yuqori yuklama stsenariysi, yangi TZ 21-bo'lim:
100 000+ events/sec): agar baza vaqtincha sekinlashsa yoki band bo'lsa,
to'g'ridan-to'g'ri yozuvchi kollektor ham sekinlashadi - bu esa UDP
paketlarni yo'qotish xavfini tug'diradi (UDP - kafolatsiz protokol,
kollektor OS bufferini o'qib ulgurmasa, paket butunlay yo'qoladi).
Navbat orqali kollektor xabarni faqat "otib yuboradi" (millisekundlar
ichida) va keyingi paketni qabul qilishga tayyor bo'ladi - baza bilan
ishlash mutlaqo alohida, mustaqil worker jarayoniga yuklatiladi.

Ishga tushirish:
    python -m collectors.syslog_server_queued
"""
import logging
import os
import socketserver
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SYSLOG_HOST, SYSLOG_PORT, LOG_LEVEL
from messaging.rabbitmq_client import publish_json

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("syslog_server_queued")

RAW_SYSLOG_QUEUE = os.getenv("RAW_SYSLOG_QUEUE", "raw_syslog_queue")


class QueuedSyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            raw_bytes = self.request[0]
            source_ip = self.client_address[0]
            message = raw_bytes.decode("utf-8", errors="replace").strip()

            success = publish_json(RAW_SYSLOG_QUEUE, {"source_ip": source_ip, "raw_message": message})
            if success:
                logger.info(f"Navbatga joylandi: {source_ip} -> {message[:60]}")
            else:
                logger.error(f"Navbatga joylashtirib bo'lmadi: {source_ip} -> {message[:60]}")
        except Exception as exc:
            logger.error(f"Paketni qayta ishlashda xatolik: {exc}")


class ThreadedSyslogServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_server():
    logger.info(f"Navbat-asosli syslog server ishga tushmoqda: {SYSLOG_HOST}:{SYSLOG_PORT} -> navbat: {RAW_SYSLOG_QUEUE}")
    server = ThreadedSyslogServer((SYSLOG_HOST, SYSLOG_PORT), QueuedSyslogUDPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server to'xtatilmoqda...")
        server.shutdown()


if __name__ == "__main__":
    run_server()
