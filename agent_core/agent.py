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
import threading

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from agent_core.file_monitor import FileMonitor
from agent_core.process_killer import kill_process_holding_file


def _default_log_file() -> str:
    """
    MUHIM (real production'da aniqlangan xato): standart nisbiy yo'l
    ("./agent.log") interaktiv rejimda ishlaganda joriy katalogga
    nisbatan muammosiz ishlaydi, lekin Windows Service LocalSystem
    hisobi ostida ishga tushirilganda standart ish katalogi
    "C:\\Windows\\System32\\" bo'ladi - bu yerga yozish (yoki modul
    import qilinayotganda FileHandler yaratish) xizmatning DARHOL,
    tushunarsiz "Cannot start service" xatosi bilan qulashiga olib
    keldi (chunki bu logging.basicConfig() chaqiruvi MODUL IMPORT
    vaqtida, hech qanday try/except'siz ishga tushadi).

    Windows'da ProgramData'ga (LocalSystem uchun ham yoziladigan,
    ish katalogiga bog'liq bo'lmagan) mutlaq yo'l ishlatamiz. Har
    qanday kutilmagan xatoda ham (masalan ProgramData'ga yoza
    olmasa) import BUZILMASLIGI uchun keng try/except bilan
    o'raymiz - eng yomon holatda oddiy nisbiy yo'lga qaytamiz.
    """
    if platform.system() != "Windows":
        return "./agent.log"
    try:
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        log_dir = os.path.join(program_data, "NetworkSecurityAgent")
        os.makedirs(log_dir, exist_ok=True)
        return os.path.join(log_dir, "agent.log")
    except OSError:
        return "./agent.log"


logging.basicConfig(
    level=os.getenv("AGENT_LOG_LEVEL", "INFO"),
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.getenv("AGENT_LOG_FILE", _default_log_file()), encoding="utf-8"),
    ],
)
logger = logging.getLogger("endpoint_agent")

# --- Sozlamalar ---
# MUHIM: standart (fallback) qiymat ataylab `http://` - `docker-compose.
# yml`ning STANDART (profilsiz) holati hamon TLS'siz (nginx reverse
# proxy - `docs_TLS_SETUP.md` - ixtiyoriy, hali auto-start emas).
# Bu yerda `https://` standart qilib qo'yish avvalgi real production
# xatosini ("OLTINCHI marta topilgan xato" - CLAUDE.md) TAKRORLAYDI -
# agent JIM ravishda ulana olmay qoladi, TLS proxy ishga tushirilmagan
# bo'lsa. TLS'ga o'tganda `API_SERVER_URL`ni ANIQ (`.env`/SYSVOL
# orqali) `https://...`ga o'zgartiring - standart qiymatga tayanmang.
API_SERVER_URL = os.getenv("API_SERVER_URL", "http://172.16.0.5:8443")
# XAVFSIZLIK: bu yerda hech qanday standart (fallback) qiymat YO'Q ataylab -
# agar server ham xuddi shunday standart bilan ishga tushirilsa (masalan
# admin AGENT_API_KEY'ni sozlashni unutsa), ikkalasi HAM bir xil ma'lum
# qatorga "kelishib qolib", tashqi hujumchi ochiq manbadan o'sha qiymatni
# o'qib API'ga kira olishi mumkin edi. AGENT_API_KEY bo'sh bo'lsa, server
# tomon eski umumiy-kalit autentifikatsiyasini butunlay o'chiradi (faqat
# per-agent token'lar orqali kirish qoladi) - shuning uchun bu yerda ham
# bo'sh qoldirish xavfsiz: so'rov shunchaki 401 bilan rad etiladi.
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
# --- TLS: ichki CA (deploy/pki/generate_ca.sh) va ixtiyoriy mTLS ---
# XAVFSIZLIK (audit topilmasi): server endi nginx orqali HTTPS bilan
# ishlaydi (docs_TLS_SETUP.md). Bizning CA tashqi (jamoat) sertifikat
# do'konlarida yo'q - shuning uchun standart `requests` tekshiruvi
# (`verify=True`) rad etadi. AGENT_CA_BUNDLE_FILE orqali shu ichki
# `ca.crt`ni ko'rsatish kerak. HECH QACHON `verify=False` ishlatilmaydi
# (bu MITM hujumiga ochiq bo'lardi) - agar CA fayli topilmasa, standart
# tizim ishonch do'koniga tayaniladi (masalan CA GPO orqali Windows
# Trusted Root'ga o'rnatilgan bo'lsa).
AGENT_CA_BUNDLE_FILE = os.getenv("AGENT_CA_BUNDLE_FILE", "")
# mTLS (ixtiyoriy, AGENT_MTLS_REQUIRED=true bo'lganda server tomon
# talab qiladi) - deploy/pki/issue_agent_cert.sh orqali chiqarilgan
# shu kompyuterga tegishli client sertifikat.
AGENT_TLS_CLIENT_CERT_FILE = os.getenv("AGENT_TLS_CLIENT_CERT_FILE", "")
AGENT_TLS_CLIENT_KEY_FILE = os.getenv("AGENT_TLS_CLIENT_KEY_FILE", "")
AGENT_VERSION = os.getenv("AGENT_VERSION", "1.0.0")
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("HEARTBEAT_INTERVAL_SECONDS", "300"))  # 5 daqiqa
LOCAL_CACHE_FILE = os.getenv(
    "AGENT_CACHE_FILE",
    os.path.join(os.path.dirname(_default_log_file()), "agent_hash_cache.json"),
)
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


def _tls_request_kwargs() -> dict:
    """
    `requests.post()`ga qo'shiladigan TLS parametrlarini bir joyda
    markazlashtiradi (3 xil chaqiruv joyida takrorlanmasligi uchun).
    `verify`: ichki CA fayli sozlangan bo'lsa o'shani, aks holda
    standart tizim ishonch do'konini ishlatadi (HECH QACHON False emas).
    `cert`: faqat ikkala mTLS fayl (sertifikat+kalit) ham sozlangan
    bo'lsagina qo'shiladi - aks holda oddiy server-tomon TLS bilan
    davom etiladi.
    """
    kwargs = {"verify": AGENT_CA_BUNDLE_FILE if AGENT_CA_BUNDLE_FILE else True}
    if AGENT_TLS_CLIENT_CERT_FILE and AGENT_TLS_CLIENT_KEY_FILE:
        kwargs["cert"] = (AGENT_TLS_CLIENT_CERT_FILE, AGENT_TLS_CLIENT_KEY_FILE)
    return kwargs


def compute_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def check_hash_with_server_or_cache(sha256: str, cache: dict, filename: str = None,
                                     hostname: str = None, ip_address: str = None) -> dict:
    """
    Avval markaziy serverga so'raydi. Server bilan bog'lanib bo'lmasa
    (offline holat) - mahalliy keshga tayanadi (fail-safe).

    MUHIM: `filename`/`hostname`/`ip_address` FAQAT server tomonida
    Dashboard'ning "Fayllar" sahifasida ko'rinish (agent haqiqatan
    fayllarni tekshirayotganining isboti) uchun yuboriladi - tekshiruv
    natijasining o'ziga ta'sir qilmaydi. Bungacha agent tomonidan
    tekshirilgan (lekin toza chiqqan) fayllar Dashboard'da HECH QAYERDA
    ko'rinmas edi - faqat zararli topilganda Alert yaratilardi, shuning
    uchun foydalanuvchi "agent fayllarni tekshirmayapti" deb noto'g'ri
    xulosaga kelishi mumkin edi.
    """
    if sha256 in cache:
        logger.debug(f"Kesh'dan topildi: {sha256[:12]}...")
        return cache[sha256]

    try:
        resp = requests.post(
            f"{API_SERVER_URL}/api/v1/check_hash",
            json={
                "sha256": sha256,
                "filename": filename,
                "hostname": hostname,
                "ip_address": ip_address,
            },
            headers={"X-API-Key": AGENT_API_KEY},
            timeout=API_TIMEOUT,
            # MUHIM (real production'da aniqlangan xato): LocalSystem
            # (Windows Service) hisobi ostida ishlaganda, `requests`
            # standart holatda MUHIT/tizim darajasidagi proksi
            # sozlamalarini (masalan Group Policy orqali o'rnatilgan
            # WinHTTP proksi) hurmat qiladi. Agar bunday proksi
            # noto'g'ri sozlangan/ishlamasa, HAR BIR so'rov
            # ConnectionResetError bilan muvaffaqiyatsiz bo'lardi -
            # garchi interaktiv foydalanuvchi sessiyasida (boshqa
            # proksi/hech qanday proksi bilan) bir xil server
            # muvaffaqiyatli javob bergan bo'lsa ham. Bizning ichki
            # server manzilimiz uchun proksi HECH QACHON kerak emas -
            # shuning uchun uni aniq o'chirib qo'yamiz.
            proxies={"http": None, "https": None},
            **_tls_request_kwargs(),
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
            proxies={"http": None, "https": None},
            **_tls_request_kwargs(),
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
            proxies={"http": None, "https": None},
            **_tls_request_kwargs(),
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
        self._heartbeat_stop = threading.Event()
        self._heartbeat_thread = None
        if not AGENT_API_KEY:
            logger.warning(
                "AGENT_API_KEY sozlanmagan - serverga barcha so'rovlar (check_hash/"
                "report_incident/heartbeat) 401 bilan rad etiladi. SYSVOL'dagi "
                "api_key.secret faylini yoki AGENT_API_KEY muhit o'zgaruvchisini tekshiring."
            )
        logger.info(f"Agent ishga tushmoqda: host={self.hostname}, ip={self.ip_address}")

    def _on_new_file(self, filepath: str):
        try:
            sha256 = compute_sha256(filepath)
        except OSError as exc:
            logger.warning(f"Faylni o'qib bo'lmadi (allaqachon o'chirilgan?): {filepath} - {exc}")
            return

        logger.info(f"Tekshirilmoqda: {filepath} (SHA256={sha256[:16]}...)")
        result = check_hash_with_server_or_cache(
            sha256, self.cache,
            filename=os.path.basename(filepath),
            hostname=self.hostname,
            ip_address=self.ip_address,
        )

        if not result.get("malicious"):
            logger.info(f"Toza: {filepath}")
            return

        threat_name = result.get("threat_name", "Noma'lum tahdid")
        logger.warning(f"ZARARLI FAYL ANIQLANDI: {filepath} [{threat_name}]")

        kill_result = kill_process_holding_file(filepath)

        file_deleted = False
        try:
            os.remove(filepath)
            file_deleted = True
            logger.warning(f"Fayl o'chirildi: {filepath}")
        except OSError as exc:
            logger.error(f"Faylni o'chirib bo'lmadi: {exc}")

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

    def _heartbeat_loop(self):
        # Send one heartbeat immediately, then periodically.
        send_heartbeat(self.hostname, self.ip_address)
        while not self._heartbeat_stop.wait(HEARTBEAT_INTERVAL_SECONDS):
            send_heartbeat(self.hostname, self.ip_address)

    def start_background(self, stop_event=None):
        """Start monitoring + heartbeat without blocking Windows SCM startup."""
        self.monitor.start()
        logger.info("Agent ishga tushdi, fayllar kuzatilmoqda...")
        self._heartbeat_stop.clear()
        self._heartbeat_thread = threading.Thread(
            target=self._heartbeat_loop,
            name="AgentHeartbeat",
            daemon=True,
        )
        self._heartbeat_thread.start()

    def stop(self):
        self._heartbeat_stop.set()
        try:
            self.monitor.stop()
        finally:
            if self._heartbeat_thread and self._heartbeat_thread.is_alive():
                self._heartbeat_thread.join(timeout=5)

    def run(self):
        self.start_background()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Agent to'xtatilmoqda...")
            self.stop()

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
