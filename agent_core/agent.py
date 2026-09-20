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
from urllib.parse import quote

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from agent_core.file_monitor import FileMonitor, is_excluded, list_local_drives
from agent_core.process_killer import kill_process_holding_file
from agent_core.quarantine import quarantine_file
from scanners.heuristic_analyzer import analyze_file


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
UPLOAD_MAX_BYTES = 25 * 1024 * 1024
MAX_SCAN_BYTES = int(os.getenv("AGENT_MAX_SCAN_BYTES", str(1024 * 1024 * 1024)))  # 1 GB
DRIVE_POLL_SECONDS = int(os.getenv("AGENT_DRIVE_POLL_SECONDS", "30"))
BULK_SERVER_DELAY = float(os.getenv("AGENT_BULK_SERVER_DELAY", "0.7"))  # server chegarasi (100/daq) ostida qolish uchun
RECHECK_INTERVAL_SECONDS = int(os.getenv("AGENT_RECHECK_INTERVAL_SECONDS", "60"))

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
    "/home", "/mnt", "/media", "/opt", "/srv",   # foydalanuvchi fayllari va ulangan disklar
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
                                     hostname: str = None, ip_address: str = None,
                                     filepath: str = None, heuristic: dict = None,
                                     prefer_cache: bool = False) -> dict:
    """
    Avval markaziy serverga so'raydi. Server bilan bog'lanib bo'lmasa
    (offline holat) - mahalliy keshga tayanadi (fail-safe).

    MUHIM: `filename`/`hostname`/`ip_address`/`filepath` FAQAT server
    tomonida Dashboard'ning "Fayllar" sahifasida ko'rinish (agent
    haqiqatan fayllarni tekshirayotganining isboti) uchun yuboriladi -
    tekshiruv natijasining o'ziga ta'sir qilmaydi. Bungacha agent
    tomonidan tekshirilgan (lekin toza chiqqan) fayllar Dashboard'da
    HECH QAYERDA ko'rinmas edi - faqat zararli topilganda Alert
    yaratilardi, shuning uchun foydalanuvchi "agent fayllarni
    tekshirmayapti" deb noto'g'ri xulosaga kelishi mumkin edi.

    `filepath` - qurilmadagi TO'LIQ yo'l (masalan "C:\\Users\\jsmith\\
    Downloads\\invoice.exe"). Ilgari faqat `filename` (fayl NOMI)
    yuborilardi - tahlilchi Dashboard'da fayl qurilmada QAYERDA
    topilganini UMUMAN ko'ra olmasdi.

    `heuristic` - `scanners.heuristic_analyzer.analyze_file()` natijasi
    (foydalanuvchi so'rovi: "unknown" fayl hech qachon qolmasin). Fayl
    MAZMUNI faqat endpoint'da mavjud (server hech qachon fayl
    baytlarini olmaydi) - shuning uchun bu ball/topilmalar shu yerda
    hisoblanib, serverga FAQAT Dashboard'dagi "Fayllar" yorlig'ini
    to'g'irlash (hash-intel hech narsa demagan "unknown"ni "clean"/
    "suspicious"ga hal qilish) uchun yuboriladi - Agent'ga qaytariladigan
    `malicious`/`confirmed` javobiga ta'sir qilmaydi (`_on_new_file()`
    heuristikni MUSTAQIL, mahalliy ravishda hisobga oladi).
    """
    # MUHIM: kesh endi FAQAT server bilan aloqa uzilganda ishlatiladi. Avval kesh
    # birinchi tekshirilardi - shu sababli bir xil fayl (xesh) boshqa joyda paydo
    # bo'lganda serverga umuman xabar bermasdi va Dashboard'da fayl QAYERDA
    # turgani (to'liq yo'l) ko'rinmasdi; kesh esa eskirgan "toza" natijani
    # ham qaytarishi mumkin edi. Endi har bir yangi fayl serverga yuboriladi.
    cached = cache.get(sha256)
    if prefer_cache and cached is not None and not cached.get("malicious"):
        return {**cached, "from_cache": True}   # ommaviy skanerlash: allaqachon toza deb ma'lum xesh

    heuristic = heuristic or {}
    try:
        resp = requests.post(
            f"{API_SERVER_URL}/api/v1/check_hash",
            json={
                "sha256": sha256,
                "filename": filename,
                "filepath": filepath,
                "hostname": hostname,
                "ip_address": ip_address,
                "magic": heuristic.get("magic"),
                "heuristic_score": heuristic.get("score"),
                "heuristic_findings": heuristic.get("findings"),
                "heuristic_verdict": heuristic.get("verdict_hint"),
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
            if result.get("upload_required") and filepath:
                uploaded = upload_for_scan(filepath, sha256, hostname)
                if uploaded is not None:
                    result = uploaded
            cache[sha256] = result
            _save_cache(cache)
            return result
        logger.warning(f"Server xatoligi: HTTP {resp.status_code}")
    except requests.RequestException as exc:
        logger.warning(f"Serverga ulanib bo'lmadi (offline rejim): {exc}")

    if cached is not None:
        logger.debug(f"Server javob bermadi, kesh'dan olindi: {sha256[:12]}...")
        return {**cached, "offline": True}

    # Server bilan bog'lanib bo'lmadi va keshda ham yo'q - xavfsizlik uchun
    # "malicious=False" deb hisoblaymiz (false-positive bilan foydalanuvchi
    # ishini to'xtatmaslik uchun), lekin bu holatni alohida belgilaymiz
    return {"malicious": False, "threat_name": None, "source": "no_data_offline", "offline": True}


def upload_for_scan(filepath: str, sha256: str, hostname: str):
    """Stream a bounded sample; upload failures preserve the hash/local decision."""
    try:
        with open(filepath, "rb") as sample:
            size = os.fstat(sample.fileno()).st_size
            if not 0 < size <= UPLOAD_MAX_BYTES:
                return None
            response = requests.post(
                f"{API_SERVER_URL}/api/v1/scan_file",
                data=sample,
                headers={"X-API-Key": AGENT_API_KEY,
                         "Content-Type": "application/octet-stream",
                         "X-Agent-Hostname": hostname or "",
                         "X-File-Name": quote(os.path.basename(filepath), safe=""),
                         "X-File-SHA256": sha256},
                timeout=(5, 120), allow_redirects=False,
                proxies={"http": None, "https": None},
                **_tls_request_kwargs(),
            )
            if response.status_code == 200:
                result = response.json()
                if result.get("sha256") == sha256:
                    return result
            logger.warning("Upload scan failed: HTTP %s", response.status_code)
    except (OSError, ValueError, requests.RequestException) as exc:
        logger.warning("Upload scan unavailable: %s", exc)
    return None


def report_incident(hostname: str, ip_address: str, filepath: str, sha256: str,
                     threat_name: str, file_deleted: bool, process_killed: bool,
                     process_name: str = None, quarantined: bool = False,
                     quarantine_path: str = None):
    payload = {
        "hostname": hostname,
        "ip_address": ip_address,
        "filename": os.path.basename(filepath),
        "filepath": filepath,
        "sha256": sha256,
        "threat_name": threat_name,
        "file_deleted": file_deleted,
        "process_killed": process_killed,
        "process_name": process_name,
        "quarantined": quarantined,
        "quarantine_path": quarantine_path,
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
        self.watch_dirs = list(watch_dirs)
        self._pending_recheck = set()
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

    def _on_new_file(self, filepath: str, bulk: bool = False) -> bool:
        """Faylni tekshiradi. Server bilan HAQIQATAN aloqa qilingan bo'lsa True (ommaviy skanerni sekinlatish uchun)."""
        try:
            if os.path.getsize(filepath) > MAX_SCAN_BYTES:
                logger.info(f"Juda katta fayl o'tkazib yuborildi (> {MAX_SCAN_BYTES} bayt): {filepath}")
                return False
            sha256 = compute_sha256(filepath)
        except OSError as exc:
            logger.warning(f"Faylni o'qib bo'lmadi (allaqachon o'chirilgan?): {filepath} - {exc}")
            return False

        # MUHIM (foydalanuvchi so'rovi: "unknown" fayl hech qachon
        # qolmasin): fayl mazmuni FAQAT shu yerda, endpoint'da mavjud -
        # server hech qachon fayl baytlarini olmaydi. Shuning uchun
        # mahalliy statik heuristika (`scanners/heuristic_analyzer.py`)
        # shu yerda hisoblanadi va (1) Dashboard'dagi yorliqni
        # to'g'irlash uchun serverga yuboriladi, (2) DETERMINISTIK
        # topilma (masalan `.pdf` deb ko'rsatilgan, aslida PE32 fayl)
        # bo'lsa - hash-intel HECH NARSA demagan taqdirda ham, MAHALLIY
        # ravishda "tasdiqlangan" deb hisoblanadi (pastga qarang).
        try:
            heuristic = analyze_file(filepath, filename=os.path.basename(filepath))
        except Exception as exc:
            logger.warning(f"Heuristik tahlil muvaffaqiyatsiz (davom etiladi): {filepath} - {exc}")
            heuristic = {}

        logger.info(f"Tekshirilmoqda: {filepath} (SHA256={sha256[:16]}...)")
        result = check_hash_with_server_or_cache(
            sha256, self.cache,
            filename=os.path.basename(filepath),
            hostname=self.hostname,
            ip_address=self.ip_address,
            filepath=filepath,
            heuristic=heuristic,
            prefer_cache=bulk,
        )
        contacted = not result.get("from_cache") and not result.get("offline")

        # MUHIM (o'zi topilgan real bug, tuzatildi): ilgari bu yerda
        # FAQAT `result.get("malicious")` tekshirilardi - bu esa
        # VirusTotal'ning TASDIQLANMAGAN (masalan 1/70 dvigatel) signali
        # bilan ham to'liq avtomatik chora (jarayonni o'ldirish, faylni
        # karantinga olish) ko'rilishiga olib kelardi, garchi shu
        # faylning `confirmed=False` ekanligi aynan shu maqsadda (soxta-
        # pozitiv xavfi) mavjud bo'lsa ham (`api/server.py::check_hash()`
        # docstring'i "FAQAT confirmed=true bo'lganda" deb hujjatlashtirgan,
        # lekin kod bunga rioya qilmagan edi). Endi avtomatik chora FAQAT
        # (a) server "confirmed" deb tasdiqlagan, YOKI (b) mahalliy
        # heuristika DETERMINISTIK "malicious" (kengaytma-nomuvofiqlik/
        # PDF tuzilmasi - soxta-pozitiv xavfi past) deb topgan holatlarda
        # ko'riladi.
        # Server bilan aloqa yo'q edi (offline/kesh) - natija ishonchsiz: aloqa tiklanganda
        # bu fayl QAYTA tekshiriladi (`_recheck_offline_loop`).
        if result.get("offline"):
            self._pending_recheck.add(filepath)
        else:
            self._pending_recheck.discard(filepath)

        server_confirmed = bool(result.get("confirmed"))
        local_confirmed = heuristic.get("verdict_hint") == "malicious"

        if not server_confirmed and not local_confirmed:
            if result.get("malicious"):
                logger.warning(
                    f"SHUBHALI (tasdiqlanmagan): {filepath} [{result.get('threat_name')}] - "
                    "avtomatik chora ko'rilmadi, qo'lda tekshirish tavsiya etiladi"
                )
            else:
                logger.info(f"Toza: {filepath}")
            return contacted

        threat_name = result.get("threat_name") or (
            "; ".join(heuristic.get("findings", [])) or "Noma'lum tahdid"
        )
        logger.warning(f"ZARARLI FAYL ANIQLANDI: {filepath} [{threat_name}]")

        kill_result = kill_process_holding_file(filepath)

        # MUHIM (o'zi topilgan bo'shliq, tuzatildi): ilgari bu yerda
        # to'g'ridan-to'g'ri xom `os.remove(filepath)` chaqirilardi -
        # hech qanday tasdiqlashsiz. `agent_core/quarantine.py::
        # quarantine_file()` (nusxa -> SHA256 orqali TASDIQLASH -> faqat
        # SHUNDAN KEYIN asl faylni o'chirish) allaqachon yozilgan va
        # test qilingan edi, lekin HECH QACHON shu yerdan chaqirilmagan
        # edi - agent hamon eski, xavfsiz bo'lmagan yo'ldan foydalanardi.
        quarantine_result = quarantine_file(filepath, sha256, threat_name)
        file_deleted = bool(quarantine_result.get("source_removed"))
        quarantined = bool(quarantine_result.get("quarantined"))
        if quarantined:
            logger.warning(f"Fayl xavfsiz karantinga olindi: {filepath} -> {quarantine_result.get('quarantine_path')}")
        else:
            logger.error(f"Faylni karantinga olib bo'lmadi: {quarantine_result.get('error')}")

        report_incident(
            hostname=self.hostname,
            ip_address=self.ip_address,
            filepath=filepath,
            sha256=sha256,
            threat_name=threat_name,
            file_deleted=file_deleted,
            process_killed=kill_result.process_killed,
            process_name=kill_result.process_name,
            quarantined=quarantined,
            quarantine_path=quarantine_result.get("quarantine_path"),
        )
        return True

    def _safe_send_heartbeat(self):
        """
        MUHIM (real production'da topilgan xato): `send_heartbeat()`ning
        o'zi faqat `requests.RequestException`ni ushlaydi - agar biror
        chaqiruvda BOSHQA turdagi kutilmagan xato (masalan tarmoq/DNS'ning
        g'alati holatidagi, `RequestException`ga o'ralmagan xatosi) yuz
        bersa, bu xato `_heartbeat_loop()`ning o'ziga chiqib ketib,
        BUTUN heartbeat thread'ini ABADIY o'ldirar edi - garchi fayl
        kuzatish (alohida thread) va `check_hash` normal davom etaversa
        ham (aynan shu holat "agent ishlayapti, lekin heartbeat bir
        marta to'xtab qolgandan keyin hech qachon qaytmagan" ko'rinishida
        production'da kuzatildi). Endi har bir urinish alohida
        himoyalangan - bitta kutilmagan xato faqat O'SHA tsiklni
        o'tkazib yuboradi, thread'ning o'zi TIRIK qoladi va keyingi
        intervalda qayta urinadi.
        """
        try:
            send_heartbeat(self.hostname, self.ip_address)
        except Exception as exc:
            logger.warning(f"Heartbeat tsiklida kutilmagan xato (thread davom etadi): {exc}")

    def _heartbeat_loop(self):
        # Send one heartbeat immediately, then periodically.
        self._safe_send_heartbeat()
        while not self._heartbeat_stop.wait(HEARTBEAT_INTERVAL_SECONDS):
            self._safe_send_heartbeat()

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
        threading.Thread(target=self._recheck_offline_loop, name="AgentRecheck", daemon=True).start()
        threading.Thread(target=self._drive_watch_loop, name="AgentDrives", daemon=True).start()
        self._maybe_start_rescan()

    def _server_reachable(self) -> bool:
        try:
            r = requests.get(f"{API_SERVER_URL}/api/v1/health", timeout=API_TIMEOUT,
                             proxies={"http": None, "https": None}, **_tls_request_kwargs())
            return r.status_code == 200
        except requests.RequestException:
            return False

    def _recheck_offline_once(self):
        """Offline paytida tekshirilgan fayllarni server tiklangach qayta tekshiradi."""
        if not self._pending_recheck or not self._server_reachable():
            return 0
        done = 0
        for path in list(self._pending_recheck):
            if not os.path.isfile(path):
                self._pending_recheck.discard(path)
                continue
            self._on_new_file(path)   # muvaffaqiyatli bo'lsa _pending_recheck'dan o'zi chiqadi
            done += 1
        if done:
            logger.info(f"Aloqa tiklandi: offline paytdagi {done} ta fayl qayta tekshirildi")
        return done

    def _recheck_offline_loop(self):
        while not self._heartbeat_stop.wait(RECHECK_INTERVAL_SECONDS):
            try:
                self._recheck_offline_once()
            except Exception as exc:
                logger.warning(f"Offline qayta tekshiruvda xato (davom etadi): {exc}")

    def _maybe_start_rescan(self):
        """
        `rescan.flag` fayli (kesh bilan bir papkada) mavjud bo'lsa, kuzatilgan papkalardagi
        MAVJUD barcha fayllar bir marta qayta tekshiriladi (odatda agent faqat YANGI fayllarni
        ko'radi). Bayroq darhol o'chiriladi - xizmat qayta ishga tushganda tsikl takrorlanmaydi.
        """
        flag = os.path.join(os.path.dirname(LOCAL_CACHE_FILE), "rescan.flag")
        if not os.path.isfile(flag):
            return
        try:
            os.remove(flag)
        except OSError as exc:
            logger.warning(f"rescan.flag o'chirib bo'lmadi, qayta skanerlash bekor qilindi: {exc}")
            return
        threading.Thread(target=self._rescan_existing, name="AgentRescan", daemon=True).start()

    def _rescan_tree(self, root_dir: str) -> int:
        """Bitta papka/diskdagi MAVJUD barcha fayllarni tekshiradi (tizim shovqini o'tkazib yuboriladi)."""
        count = 0
        for dirpath, dirs, files in os.walk(root_dir):
            dirs[:] = [d for d in dirs if not is_excluded(os.path.join(dirpath, d))]
            for name in files:
                if self._heartbeat_stop.is_set():
                    return count
                path = os.path.join(dirpath, name)
                if is_excluded(path):
                    continue
                try:
                    contacted = self._on_new_file(path, bulk=True)
                    count += 1
                    if contacted:
                        time.sleep(BULK_SERVER_DELAY)   # server so'rov chegarasi (daqiqasiga) ostida qolish
                except Exception as exc:
                    logger.warning(f"Qayta skanerlashda xato ({name}): {exc}")
        return count

    def _rescan_existing(self):
        logger.info("Qayta skanerlash boshlandi: mavjud fayllar tekshirilmoqda...")
        count = 0
        for root_dir in list(self.monitor.watch_dirs):
            count += self._rescan_tree(root_dir)
        logger.info(f"Qayta skanerlash tugadi: {count} ta fayl tekshirildi")

    def _drive_watch_once(self):
        """Yangi ulangan disk (USB/flesh) topilsa - kuzatuvga qo'shadi va undagi mavjud fayllarni tekshiradi."""
        for root in list_local_drives():
            if root not in self.monitor.watch_dirs and self.monitor.add_dir(root):
                logger.info(f"Yangi disk ulandi: {root} - undagi fayllar tekshirilmoqda")
                threading.Thread(target=self._rescan_tree, args=(root,), name="AgentDriveScan", daemon=True).start()

    def _drive_watch_loop(self):
        while not self._heartbeat_stop.wait(DRIVE_POLL_SECONDS):
            try:
                self._drive_watch_once()
            except Exception as exc:
                logger.warning(f"Disk kuzatuvida xato (davom etadi): {exc}")

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
