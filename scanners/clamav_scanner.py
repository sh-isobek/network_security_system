"""
ClamAV Scanner - 4-bosqichni kengaytirish.

`clamscan` CLI vositasi orqali ishlaydi (`clamd` daemon shart emas - bizning
pipeline'imiz batch/navbat asosida ishlaydi, real-vaqt daemon kerak emas,
bu esa production'da soddaroq va barqarorroq).

MUHIM (Production uchun): virus bazasini yangilab turish uchun
`freshclam` cron orqali muntazam ishga tushirilishi SHART:

    # /etc/cron.d/freshclam (odatda paket o'rnatilganda avtomatik qo'shiladi)
    0 */2 * * * root freshclam --quiet

Agar baza eskirgan bo'lsa (`/var/lib/clamav/` papkasida `.cvd`/`.cld`
fayllari yo'q yoki eski bo'lsa), `clamscan` xato qaytarishi yoki hech
narsa topmasligi mumkin - shuning uchun bu modul bazaning mavjudligini
oldindan tekshiradi va yo'q bo'lsa aniq ogohlantirish beradi.
"""
import glob
import logging
import os
import socket
import struct
import subprocess
from typing import Optional

logger = logging.getLogger("clamav_scanner")

CLAMSCAN_BIN = os.getenv("CLAMSCAN_BIN", "clamscan")
CLAMAV_DB_DIR = os.getenv("CLAMAV_DB_DIR", "/var/lib/clamav")
CLAMSCAN_TIMEOUT = int(os.getenv("CLAMSCAN_TIMEOUT", "30"))

# clamd (doimiy jarayon, `docker-compose.yml`dagi `clamav_updater` xizmati ichida) - sozlansa
# (CLAMD_HOST bo'sh bo'lmasa) BIRINCHI navbatda ishlatiladi: baza xotirada bir marta yuklangani
# uchun `clamscan` CLI'dan (har chaqiruvda ~180MB bazani qayta yuklaydi) SEZILARLI tezroq, va
# fayl BAYTLARINI tarmoq orqali yuboradi (INSTREAM) - chaqiruvchi konteynerga umuman umumiy
# `/var/lib/clamav` volume ulanishi shart emas (masalan `agent_api`ning yuklangan namunalarni
# skanerlashi uchun). CLAMD_HOST bo'sh bo'lsa (standart) - bu modul avvalgidek FAQAT `clamscan`
# CLI orqali ishlaydi (orqaga moslik, hech qanday xatti-harakat o'zgarishi yo'q).
CLAMD_HOST = os.getenv("CLAMD_HOST", "")
CLAMD_PORT = int(os.getenv("CLAMD_PORT", "3310"))
CLAMD_TIMEOUT = int(os.getenv("CLAMD_TIMEOUT", "30"))

# clamscan exit code'lari: 0=toza, 1=virus topildi, 2=xatolik
EXIT_CLEAN = 0
EXIT_INFECTED = 1


def is_database_available() -> bool:
    """Virus bazasi papkasida kamida bitta .cvd/.cld/.hdb/.ndb fayl bormi."""
    patterns = ["*.cvd", "*.cld", "*.hdb", "*.ndb"]
    for pattern in patterns:
        if glob.glob(os.path.join(CLAMAV_DB_DIR, pattern)):
            return True
    return False


def clamd_available(host: Optional[str] = None, port: Optional[int] = None, timeout: int = 3) -> bool:
    """clamd bilan bog'lanish mumkinmi (zPING\0 -> PONG). Tez, arzon tekshiruv - har bir fayl
    uchun emas, `scan_file()`ning o'zi ichida (fallback qarorini qabul qilishdan oldin) chaqiriladi."""
    host = host or CLAMD_HOST
    if not host:
        return False
    port = port or CLAMD_PORT
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"zPING\0")
            return sock.recv(64).startswith(b"PONG")
    except OSError:
        return False


def _parse_clamd_response(text: str) -> dict:
    text = text.strip()
    if text.endswith(" FOUND"):
        body = text[: -len(" FOUND")]
        sig = body.split(": ", 1)[1].strip() if ": " in body else body.strip()
        return {"scanned": True, "infected": True, "signature": sig or "Noma'lum signatura", "error": None}
    if text.endswith(" OK"):
        return {"scanned": True, "infected": False, "signature": None, "error": None}
    return {"scanned": False, "infected": False, "signature": None, "error": f"clamd: {text or 'javob yo\'q'}"}


def scan_file_via_clamd(filepath: str, host: Optional[str] = None, port: Optional[int] = None,
                         timeout: Optional[int] = None) -> Optional[dict]:
    """
    Faylni clamd'ga INSTREAM protokoli orqali (rasmiy ClamAV protokoli - 4 baytli katta-endian
    uzunlik + bo'lak, oxirida 0-uzunlikli bo'lak) baytlarini oqim sifatida yuboradi - fayl
    clamd konteynerida jismonan mavjud bo'lishi SHART EMAS. Ulanish/protokol xatosida `None`
    qaytaradi (chaqiruvchi `clamscan` CLI'ga zaxira sifatida o'tishi uchun).
    """
    host = host or CLAMD_HOST
    port = port or CLAMD_PORT
    timeout = timeout or CLAMD_TIMEOUT
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(b"zINSTREAM\0")
            with open(filepath, "rb") as fh:
                while True:
                    chunk = fh.read(65536)
                    if not chunk:
                        break
                    sock.sendall(struct.pack("!L", len(chunk)) + chunk)
            sock.sendall(struct.pack("!L", 0))
            buf = b""
            while b"\0" not in buf:
                data = sock.recv(4096)
                if not data:
                    break
                buf += data
    except OSError as exc:
        logger.warning(f"clamd bilan bog'lanib bo'lmadi ({host}:{port}): {exc}")
        return None
    return _parse_clamd_response(buf.split(b"\0", 1)[0].decode("utf-8", errors="replace"))


def scan_file(filepath: str, extra_db_dir: Optional[str] = None,
              temp_dir: Optional[str] = None) -> dict:
    """
    Faylni ClamAV orqali skanerlaydi.

    Qaytaradi: {
        "scanned": bool,       # skanerlash muvaffaqiyatli o'tdimi
        "infected": bool,
        "signature": str|None, # topilgan signatura nomi
        "error": str|None,
    }
    """
    if not os.path.isfile(filepath):
        return {"scanned": False, "infected": False, "signature": None, "error": "Fayl topilmadi"}

    # `extra_db_dir` beruvchi chaqiruvchilar (masalan test-maxsus signatura fayli) clamd'ning
    # UMUMIY (rasmiy) bazasidan farqli, o'zining alohida bazasini kutadi - bu holatda har doim
    # CLI (`clamscan -d <dir>`) ishlatiladi, clamd chetlab o'tiladi.
    if extra_db_dir is None and CLAMD_HOST and clamd_available():
        result = scan_file_via_clamd(filepath)
        if result is not None:
            return result
        logger.warning("clamd javob bermadi, zaxira sifatida 'clamscan' CLI ishlatilmoqda")

    db_dir = extra_db_dir or CLAMAV_DB_DIR
    if not is_database_available() and not extra_db_dir:
        return {
            "scanned": False, "infected": False, "signature": None,
            "error": "ClamAV virus bazasi topilmadi - 'freshclam' ishga tushirilishi kerak",
        }

    cmd = [CLAMSCAN_BIN, "--no-summary", "-d", db_dir, filepath]
    if temp_dir is not None:
        # Upload scans own this directory, including decompression artifacts
        # left behind when the child scanner is killed on timeout.
        cmd[1:1] = ["--tempdir", temp_dir]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CLAMSCAN_TIMEOUT)
    except FileNotFoundError:
        return {"scanned": False, "infected": False, "signature": None,
                 "error": "clamscan topilmadi - 'apt install clamav' bilan o'rnating"}
    except subprocess.TimeoutExpired:
        return {"scanned": False, "infected": False, "signature": None,
                 "error": f"clamscan timeout ({CLAMSCAN_TIMEOUT}s)"}

    if result.returncode == EXIT_CLEAN:
        return {"scanned": True, "infected": False, "signature": None, "error": None}

    if result.returncode == EXIT_INFECTED:
        # Chiqish namunasi: "/path/to/file: Win.Trojan.Generic FOUND"
        signature = None
        for line in result.stdout.splitlines():
            if line.strip().endswith("FOUND"):
                signature = line.split(":", 1)[1].strip().rsplit(" ", 1)[0].strip()
                break
        return {"scanned": True, "infected": True, "signature": signature or "Noma'lum signatura", "error": None}

    # returncode == 2 yoki boshqa - xatolik
    return {"scanned": False, "infected": False, "signature": None,
             "error": f"clamscan xatoligi (kod={result.returncode}): {result.stderr.strip()[:200]}"}
