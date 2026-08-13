"""
Windows Endpoint Agent - 6-bosqich, asosiy dastur.

Vazifasi (TZ talabiga mos):
  "Windows Agent orqali fayl o'chiriladi va jarayon to'xtatiladi"

Ish jarayoni:
  1. Xavfli papkalarni kuzatadi (Downloads, Desktop, Temp, Outlook
     Attachments) - FileMonitor orqali.
  2. Yangi fayl paydo bo'lib, barqarorlashgach - SHA256 hisoblaydi.
  3. Markaziy API'ga (/api/v1/check_hash) so'rov yuboradi.
     - Agar server bilan bog'lanib bo'lmasa (masalan noutbuk ofisdan
       tashqarida) - MAHALLIY kesh (cache) fayliga tayanadi (fail-safe:
       server ishlamasa ham asosiy himoya davom etadi).
  4. Agar zararli deb topilsa:
       a) Faylni ochiq ushlab turgan jarayonni topib to'xtatadi
          (process_killer orqali).
       b) Faylni diskdan o'chiradi.
       c) Markazga /api/v1/report_incident orqali xabar beradi.
  5. Har bir harakat mahalliy log fayliga ham yoziladi (server bilan
     aloqa uzilgan taqdirda ham audit iz qolishi uchun).

Ishga tushirish (test/dev, Windows'da ham, Linux'da ham ishlaydi):
    python -m windows_agent.agent

Production'da Windows Service sifatida - service_wrapper.py orqali
(docs_WINDOWS_AGENT_SETUP.md'da to'liq yo'riqnoma).
"""
import argparse
import hashlib
import json
import logging
import os
import platform
import socket
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from agent_core.file_monitor import FileMonitor
from agent_core.process_killer import kill_process_holding_file

logging.basicConfig(
    level=os.getenv("AGENT_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.getenv("AGENT_LOG_FILE", "./agent.log"), encoding="utf-8"),
    ],
)
logger = logging.getLogger("endpoint_agent")

# --- Sozlamalar ---
API_SERVER_URL = os.getenv("API_SERVER_URL", "http://172.16.0.5:8443")
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "change-me-in-production")
AGENT_VERSION = os.getenv("AGENT_VERSION", "1.0.0")
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "300"))  # 5 daqiqa
LOCAL_CACHE_FILE = os.getenv("AGENT_CACHE_FILE", "./agent_hash_cache.json")
API_TIMEOUT = 5  # soniya - server sekin javob bersa ham foydalanuvchini kutdirmaslik uchun

DEFAULT_WATCH_DIRS_WINDOWS = [
    os.path.expandvars(r"%USERPROFILE%\Downloads"),
    os.path.expandvars(r"%USERPROFILE%\Desktop"),
    os.path.expandvars(r"%TEMP%"),
    os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Outlook"),
]

DEFAULT_WATCH_DIRS_LINUX = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    "/tmp",
    "/var/tmp",
]

DEFAULT_WATCH_DIRS_MACOS = [
    os.path.expanduser("~/Downloads"),
    os.path.expanduser("~/Desktop"),
    "/tmp",
]


def _load_cache() -> dict:
    if os.path.isfile(LOCAL_CACHE_FILE):
        try:
            with open(LOCAL_CACHE_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError):
            return {}
    return {}


def _save_cache(cache: dict):
    try:
        with open(LOCAL_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError as exc:
        logger.error(f"Keshni saqlab bo'lmadi: {exc}")


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_hash_with_server_or_cache(sha256: str, cache: dict) -> dict:
    """
    Avval markaziy serverga so'raydi. Server bilan bog'lanib bo'lmasa
    (offline holat) - mahalliy keshga tayanadi (fail-safe).
    """
    if sha256 in cache:
        logger.debug(f"Kesh'dan topildi: {sha256[:12]}...")
        return cache[sha256]

    try:
        resp = requests.post(
            f"{API_SERVER_URL}/api/v1/check_hash",
            json={"sha256": sha256},
            headers={"X-API-Key": AGENT_API_KEY},
            timeout=API_TIMEOUT,
        )
        if resp.status_code == 200:
            result = resp.json()
            cache[sha256] = result
            _save_cache(cache)
            return result
        logger.warning(f"Server xatoligi: HTTP {resp.status_code}")
    except requests.RequestException as exc:
        logger.warning(f"Serverga ulanib bo'lmadi (offline rejim): {exc}")

    # Server bilan bog'lanib bo'lmadi va keshda ham yo'q - xavfsizlik uchun
    # "malicious=False" deb hisoblaymiz (false-positive bilan foydalanuvchi
    # ishini to'xtatmaslik uchun), lekin bu holatni alohida belgilaymiz
    return {"malicious": False, "threat_name": None, "source": "no_data_offline"}


def report_incident(hostname: str, ip_address: str, filepath: str, sha256: str,
                     threat_name: str, file_deleted: bool, process_killed: bool,
                     process_name: str = None):
    payload = {
        "hostname": hostname,
        "ip_address": ip_address,
        "filename": os.path.basename(filepath),
        "sha256": sha256,
        "threat_name": threat_name,
        "file_deleted": file_deleted,
        "process_killed": process_killed,
        "process_name": process_name,
    }
    try:
        resp = requests.post(
            f"{API_SERVER_URL}/api/v1/report_incident",
            json=payload,
            headers={"X-API-Key": AGENT_API_KEY},
            timeout=API_TIMEOUT,
        )
        if resp.status_code == 200:
            logger.info(f"Markazga xabar berildi: {resp.json()}")
        else:
            logger.error(f"Markazga xabar berishda xatolik: HTTP {resp.status_code}")
    except requests.RequestException as exc:
        logger.error(f"Markazga xabar berib bo'lmadi (offline): {exc}")
        # TODO: offline navbat (queue) qo'shish - internet qaytganda qayta yuborish


def send_heartbeat(hostname: str, ip_address: str) -> bool:
    """
    Markazga "men tirikman" xabarini yuboradi -
    `network_discovery.agent_coverage` moduli buni "qaysi AD
    kompyuterda agent hali o'rnatilmagan/to'xtagan" hisobotini
    chiqarish uchun ishlatadi. Xatolik (offline) bo'lsa jim ravishda
    False qaytaradi - agentning asosiy vazifasini (fayl kuzatish)
    to'xtatib qo'ymaydi.
    """
    payload = {
        "hostname": hostname,
        "ip_address": ip_address,
        "agent_version": AGENT_VERSION,
        "agent_os": platform.system().lower().replace("darwin", "mac"),
    }
    try:
        resp = requests.post(
            f"{API_SERVER_URL}/api/v1/agent_heartbeat",
            json=payload,
            headers={"X-API-Key": AGENT_API_KEY},
            timeout=API_TIMEOUT,
        )
        return resp.status_code == 200
    except requests.RequestException as exc:
        logger.debug(f"Heartbeat yuborib bo'lmadi (offline): {exc}")
        return False


def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"


class EndpointAgent:
    def __init__(self, watch_dirs):
        self.hostname = platform.node()
        self.ip_address = _get_local_ip()
        self.cache = _load_cache()
        self.monitor = FileMonitor(watch_dirs, self._on_new_file)
        logger.info(f"Agent ishga tushmoqda: host={self.hostname}, ip={self.ip_address}")

    def _on_new_file(self, filepath: str):
        try:
            sha256 = compute_sha256(filepath)
        except OSError as exc:
            logger.warning(f"Faylni o'qib bo'lmadi (allaqachon o'chirilgan?): {filepath} - {exc}")
            return

        logger.info(f"Tekshirilmoqda: {filepath} (SHA256={sha256[:16]}...)")
        result = check_hash_with_server_or_cache(sha256, self.cache)

        if not result.get("malicious"):
            logger.info(f"Toza: {filepath}")
            return

        threat_name = result.get("threat_name", "Noma'lum tahdid")
        logger.warning(f"ZARARLI FAYL ANIQLANDI: {filepath} [{threat_name}]")

        # 1) Jarayonni to'xtatish
        kill_result = kill_process_holding_file(filepath)

        # 2) Faylni o'chirish
        file_deleted = False
        try:
            os.remove(filepath)
            file_deleted = True
            logger.warning(f"Fayl o'chirildi: {filepath}")
        except OSError as exc:
            logger.error(f"Faylni o'chirib bo'lmadi: {exc}")

        # 3) Markazga xabar berish
        report_incident(
            hostname=self.hostname,
            ip_address=self.ip_address,
            filepath=filepath,
            sha256=sha256,
            threat_name=threat_name,
            file_deleted=file_deleted,
            process_killed=kill_result.process_killed,
            process_name=kill_result.process_name,
        )

    def run(self):
        self.monitor.start()
        logger.info("Agent ishga tushdi, fayllar kuzatilmoqda...")
        send_heartbeat(self.hostname, self.ip_address)  # ishga tushganda darhol bir marta
        last_heartbeat = time.time()
        try:
            while True:
                time.sleep(1)
                if time.time() - last_heartbeat >= HEARTBEAT_INTERVAL_SECONDS:
                    send_heartbeat(self.hostname, self.ip_address)
                    last_heartbeat = time.time()
        except KeyboardInterrupt:
            logger.info("Agent to'xtatilmoqda...")
            self.monitor.stop()


def _default_watch_dirs():
    system = platform.system()
    if system == "Windows":
        return DEFAULT_WATCH_DIRS_WINDOWS
    if system == "Darwin":
        return DEFAULT_WATCH_DIRS_MACOS
    # Linux (va noma'lum/test muhitlari uchun standart)
    return DEFAULT_WATCH_DIRS_LINUX


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--watch-dirs", nargs="+", default=None, help="Kuzatiladigan papkalar ro'yxati")
    args = ap.parse_args()

    dirs = args.watch_dirs or _default_watch_dirs()
    agent = EndpointAgent(dirs)
    agent.run()
