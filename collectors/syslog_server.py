"""
Syslog Qabul Qiluvchi (Collector) - 0-bosqich.

Vazifasi:
  1. UDP portda tinglaydi (Kerio Control, switchlar, UniFi shu yerga
     loglarini yuborishi kerak).
  2. Har bir kelgan xabarni:
       a) xom holda RAW_LOG_FILE fayliga yozadi (audit uchun),
       b) ma'lumotlar bazasidagi raw_logs jadvaliga saqlaydi
          (keyingi bosqichda parser shu yozuvlarni o'qib qayta ishlaydi).
  3. Ko'p qurilmadan bir vaqtda log kelishiga chidamli bo'lishi uchun
     ThreadingUDPServer ishlatiladi (har bir paket alohida thread'da
     qayta ishlanadi, server bloklanib qolmaydi).

Ishga tushirish:
    python -m collectors.syslog_server

Eslatma: 514-port <1024 bo'lgani uchun production'da root/systemd
CAP_NET_BIND_SERVICE huquqi kerak. Test uchun config/settings.py'da
SYSLOG_PORT=5140 qoldiring.
"""
import logging
import os
import socketserver
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import SYSLOG_HOST, SYSLOG_PORT, RAW_LOG_FILE, LOG_LEVEL
from db.database import get_session
from db.models import RawLog, utcnow

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("syslog_server")

# RAW_LOG_FILE papkasi mavjudligiga ishonch hosil qilamiz
os.makedirs(os.path.dirname(RAW_LOG_FILE), exist_ok=True)


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """Har bir kelgan UDP paketni qayta ishlaydigan handler."""

    def handle(self):
        try:
            raw_bytes = self.request[0]
            source_ip = self.client_address[0]

            # Syslog xabarlari odatda ASCII/UTF-8, lekin xato belgilar
            # tizimni to'xtatib qo'ymasligi uchun errors="replace" ishlatamiz
            message = raw_bytes.decode("utf-8", errors="replace").strip()

            self._write_to_file(source_ip, message)
            self._write_to_db(source_ip, message)

            logger.info(f"Log qabul qilindi: {source_ip} -> {message[:80]}")

        except Exception as exc:
            # Bitta noto'g'ri paket butun serverni to'xtatib qo'ymasligi kerak
            logger.error(f"Paketni qayta ishlashda xatolik: {exc}")

    @staticmethod
    def _write_to_file(source_ip: str, message: str):
        timestamp = utcnow().isoformat()
        with open(RAW_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"{timestamp}\t{source_ip}\t{message}\n")

    @staticmethod
    def _write_to_db(source_ip: str, message: str):
        session = get_session()
        try:
            entry = RawLog(source_ip=source_ip, raw_message=message)
            session.add(entry)
            session.commit()
        except Exception as exc:
            session.rollback()
            logger.error(f"Bazaga yozishda xatolik: {exc}")
        finally:
            session.close()


class ThreadedSyslogServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    """Ko'p paketni parallel qayta ishlash uchun threading UDP server."""
    allow_reuse_address = True
    daemon_threads = True


def run_server():
    logger.info(f"Syslog server ishga tushmoqda: {SYSLOG_HOST}:{SYSLOG_PORT}")
    server = ThreadedSyslogServer((SYSLOG_HOST, SYSLOG_PORT), SyslogUDPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server to'xtatilmoqda...")
        server.shutdown()


if __name__ == "__main__":
    run_server()
