"""
Suricata eve.json Reader - 2-bosqich.

Suricata `eve.json`ga JSON Lines formatida yozadi (har qatorda bitta
hodisa). Bu modul faylni "tail -f" uslubida kuzatib boradi va faqat
`"event_type": "fileinfo"` yozuvlarini oladi (fayl transferlari haqida
- boshqa event turlari, masalan flow/dns, bu bosqichda kerak emas,
chunki DNS allaqachon alohida Windows DNS parser orqali qamrab olingan).

MUHIM (real arxitektura bo'shlig'i tuzatilgan - foydalanuvchining
chuqur tahlilidagi ②-band): avval `FileEvent.stored_path` HECH QACHON
to'ldirilmasdi - `engine/deep_scan_engine.py` (YARA/ClamAV/Office/
Archive) FAQAT `stored_path` mavjud bo'lganda ishlay oladi, shuning
uchun Suricata orqali kelgan fayllar uchun bu tekshiruvlarning
BARCHASI jimgina o'tkazib yuborilardi - faqat hash (VT/MalwareBazaar/
local blacklist) natijasiga tayanilardi. Endi `fileinfo.stored`
(Suricata bu faylni HAQIQATAN diskka saqladimi - `file-store` qoidasi
mos kelgan bo'lsa) `true` bo'lsa, `stored_path` `SURICATA_FILESTORE_
DIR` (standart: `/var/log/suricata/files`, `docs_SURICATA_SETUP.md`
bilan bir xil) + SHA256 sifatida hisoblab qo'yiladi - bu Suricata
`file-store: version: 2` sozlamasining HAQIQIY fayl nomlash
konvensiyasi (rasmiy hujjatlarga muvofiq: fayl to'g'ridan-to'g'ri
`<dir>/<sha256>` sifatida, ichki papkalarsiz saqlanadi). Eski
`file-store: version: 1` (endi eskirgan) boshqa, ichma-ich papka
konvensiyasidan foydalanadi - bu yerda QO'LLAB-QUVVATLANMAYDI (`docs_
SURICATA_SETUP.md` `version: 2`ni talab qiladi).

Bu modul o'zi (`suricata_reader`, docker-compose'da eve.json'ni
o'qiydigan xizmat) `/var/log/suricata/files` papkasiga ULANMAGAN -
faqat YO'L QATORINI yozadi. Haqiqiy faylni KEYINROQ `deep_scan_engine`
xizmati (o'sha papka unga bog'langan) ochib tekshiradi - ikkalasi ham
bir xil host katalogini bir xil konteyner yo'liga bog'lagani uchun
yo'l qatori ikkalasida ham bir xil ma'noga ega bo'ladi.

Ishga tushirish:
    python -m collectors.suricata_reader --file /var/log/suricata/eve.json
"""
import argparse
import json
import logging
import os
import stat
import sys
import time
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import FileEvent

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("suricata_reader")


def _guess_channel(filename: str, dest_ip: str = None) -> str:
    """Fayl manbasini (Telegram/Email/Web) taxminiy aniqlash - keyingi
    bosqichlarda HTTP header/SNI asosida aniqroq qilinadi."""
    if not filename:
        return "unknown"
    lower = filename.lower()
    if "telegram" in lower:
        return "telegram"
    return "web"


def _own_endpoints():
    """O'z agent API serverimiz (host, port) juftliklari - `API_SERVER_URL`
    va ixtiyoriy `SURICATA_IGNORE_ENDPOINTS` ("host:port,host:port")."""
    endpoints = set()
    url = os.getenv("API_SERVER_URL", "").strip()
    if url:
        parsed = urlparse(url)
        if parsed.hostname:
            endpoints.add((parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)))
    for item in os.getenv("SURICATA_IGNORE_ENDPOINTS", "").split(","):
        host, _, port = item.strip().rpartition(":")
        if host and port.isdigit():
            endpoints.add((host.lower(), int(port)))
    return endpoints


_OWN_ENDPOINTS = _own_endpoints()


def _is_noise(event: dict) -> bool:
    """Tarmoqdagi haqiqiy fayl emas - o'tkazib yuboriladi.

    Real production topilmasi: Suricata ishga tushgach, eve.json'dagi
    fileinfo'larning 100%i Endpoint Agentlarning o'z serverimizga
    (`API_SERVER_URL`) yuboradigan heartbeat/watchdog JSON tanalari edi -
    ular Fayllar sahifasini to'ldirar va hash tekshiruvlarini behuda
    sarflardi. Agent serverga yuklagan shubhali fayl esa allaqachon
    `endpoint_upload` sifatida yozilgan - ikkinchi marta kerak emas.
    """
    magic = (event.get("fileinfo") or {}).get("magic") or ""
    if magic.startswith("JSON"):
        return True
    hostname = ((event.get("http") or {}).get("hostname") or "").lower()
    for host, port in _OWN_ENDPOINTS:
        if (event.get("dest_ip") == host or hostname == host) and event.get("dest_port") == port:
            return True
        if event.get("src_ip") == host and event.get("src_port") == port:
            return True
    return False


def process_fileinfo_event(session, event: dict) -> bool:
    """Bitta Suricata fileinfo JSON yozuvini file_events jadvaliga yozadi.
    Qaytaradi: True - yangi yozuv qo'shildi, False - o'tkazib yuborildi
    (hash yo'q yoki takroriy)."""
    fileinfo = event.get("fileinfo", {})
    sha256 = fileinfo.get("sha256")
    if not sha256:
        return False  # hash hisoblanmagan fayl - o'tkazib yuboramiz
    if _is_noise(event):
        return False

    # Bir xil hash+src_ip juftligi qayta yozilmasligi uchun oddiy tekshiruv
    exists = (
        session.query(FileEvent)
        .filter(FileEvent.sha256 == sha256, FileEvent.src_ip == event.get("src_ip"))
        .first()
    )
    if exists:
        return False

    filename = fileinfo.get("filename", "")
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else None

    # MUHIM (real arxitektura bo'shlig'i tuzatilgan): `fileinfo.stored`
    # FAQAT bu aniq fayl `filestore;` qoidasiga mos kelib, HAQIQATAN
    # diskka yozilganda `true` bo'ladi - `force-hash` orqali hash HAR
    # BIR ko'rilgan fayl uchun hisoblanadi, lekin bu ularning BARCHASI
    # saqlangani degani EMAS. `stored=false`/yo'q bo'lsa, `stored_path`
    # bo'sh qoldiriladi (aks holda mavjud bo'lmagan faylga yo'l
    # ko'rsatib qo'yamiz - `deep_scan_engine.py` buni baribir xavfsiz
    # o'tkazib yuboradi, lekin noto'g'ri bo'lardi).
    stored_path = None
    if fileinfo.get("stored"):
        filestore_dir = os.getenv("SURICATA_FILESTORE_DIR", "/var/log/suricata/files")
        stored_path = os.path.join(filestore_dir, sha256)

    entry = FileEvent(
        src_ip=event.get("src_ip"),
        dest_ip=event.get("dest_ip"),
        filename=filename,
        file_ext=file_ext,
        magic=fileinfo.get("magic"),
        size=fileinfo.get("size"),
        sha256=sha256,
        md5=fileinfo.get("md5"),
        protocol=event.get("proto") or event.get("app_proto"),
        channel=_guess_channel(filename),
        stored_path=stored_path,
        checked=False,
    )
    session.add(entry)
    stored_note = " [file-store'da saqlangan]" if stored_path else " [faqat hash - fayl saqlanmagan]"
    logger.info(f"Fayl aniqlandi: {filename} ({sha256[:12]}...) {event.get('src_ip')} -> {event.get('dest_ip')}{stored_note}")
    return True


def read_existing(filepath: str):
    """Fayldagi mavjud barcha qatorlarni bir martalik o'qiydi (test/backlog uchun)."""
    session = get_session()
    count = 0
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") == "fileinfo":
                    if process_fileinfo_event(session, event):
                        count += 1
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
    return count


def _process_line(line: str):
    line = line.strip()
    if not line:
        return
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return
    if event.get("event_type") != "fileinfo":
        return
    session = get_session()
    try:
        process_fileinfo_event(session, event)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"Xatolik: {exc}")
    finally:
        session.close()


def follow_file(filepath: str, interval: float = 1.0, stop=None):
    """eve.json faylini tail -F uslubida doimiy kuzatadi.

    MUHIM (real production xatosi tuzatilgan): avval fayl yo'q bo'lsa yoki
    uning o'rnida papka bo'lsa (Docker yo'q faylni bind-mount qilganda
    shunday papka yaratib qo'yadi) xizmat `IsADirectoryError` bilan
    yiqilib, cheksiz qayta ishga tushardi. Logrotate faylni almashtirganda
    (yangi inode) yoki qisqartirganda esa eski faylga yopishib qolib,
    yangi hodisalarni ko'rmasdi. Endi:
      - fayl paydo bo'lguncha xatosiz kutadi;
      - birinchi ochishda faylning OXIRIDAN boshlaydi (eski backlog
        qayta yozilmaydi), aylantirilgan YANGI faylni esa BOSHIDAN o'qiydi;
      - qisqartirilib qayta yozilgan faylni (hatto hajmi avvalgidek yoki
        kattaroq bo'lsa ham - oxirgi o'qilgan qator joyida yo'qligidan)
        aniqlaydi;
      - chala yozilgan (hali `\\n` bilan tugamagan) qatorni yo'qotmaydi.
    Fayl binar rejimda o'qiladi - `tell()`/`seek()` aniq bayt pozitsiyasi.
    `stop` - testlar uchun `threading.Event`.
    """
    f = None
    inode = None
    first_open = True
    waiting_logged = False
    partial = b""
    last_line = b""        # oxirgi to'liq o'qilgan qator (qayta yozilganini aniqlash uchun)
    seen_mtime = None
    while stop is None or not stop.is_set():
        if f is None:
            if not os.path.isfile(filepath):
                if not waiting_logged:
                    kind = "papka (fayl emas)" if os.path.isdir(filepath) else "mavjud emas"
                    logger.warning(f"{filepath} {kind} - Suricata faylni yaratishi kutilmoqda")
                    waiting_logged = True
                time.sleep(interval)
                continue
            f = open(filepath, "rb")
            inode = os.fstat(f.fileno()).st_ino
            if first_open:
                f.seek(0, os.SEEK_END)
            first_open = False
            waiting_logged = False
            partial, last_line, seen_mtime = b"", b"", None
            logger.info(f"eve.json kuzatilmoqda: {filepath}")

        chunk = f.readline()
        if chunk:
            partial += chunk
            if partial.endswith(b"\n"):
                _process_line(partial.decode("utf-8", errors="replace"))
                last_line = partial
                partial = b""
            continue

        # Fayl oxiri. Kutib, YANGI ma'lumotni o'qishdan OLDIN tekshiramiz:
        # aylantirildimi (boshqa inode / o'chirildi) yoki qisqartirildimi?
        time.sleep(interval)
        try:
            st = os.stat(filepath)
        except OSError:
            # Nomi o'zgartirilgan, yangisi hali yaratilmagan (logrotate oralig'i):
            # Suricata HUP olguncha eski faylga yozadi - shundan o'qishda davom etamiz.
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        if st.st_ino != inode:
            # Aylantirilgan eski faylga oxirgi lahzada yozilgan qatorlarni ham olamiz
            for rest in f:
                partial += rest
                if partial.endswith(b"\n"):
                    _process_line(partial.decode("utf-8", errors="replace"))
                    partial = b""
            f.close()
            f = None
            continue
        pos = f.tell()
        rewritten = st.st_size < pos
        if not rewritten and last_line and st.st_mtime_ns != seen_mtime:
            # Fayl yozilgan (hajmi avvalgidek yoki kattaroq): oxirgi o'qilgan
            # qatorimiz hali joyidami? Yo'q bo'lsa - qisqartirilib qayta yozilgan.
            f.seek(pos - len(last_line) - len(partial))
            rewritten = f.read(len(last_line)) != last_line
            f.seek(pos)
        seen_mtime = st.st_mtime_ns
        if rewritten:
            f.seek(0)
            partial, last_line = b"", b""
    if f is not None:
        f.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default="/var/log/suricata/eve.json")
    ap.add_argument("--once", action="store_true", help="Mavjud faylni bir marta o'qib chiqish (test uchun)")
    args = ap.parse_args()

    if args.once:
        n = read_existing(args.file)
        logger.info(f"{n} ta fileinfo yozuvi qayta ishlandi")
    else:
        follow_file(args.file)
