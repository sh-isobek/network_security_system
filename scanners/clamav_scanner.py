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
import subprocess
from typing import Optional

logger = logging.getLogger("clamav_scanner")

CLAMSCAN_BIN = os.getenv("CLAMSCAN_BIN", "clamscan")
CLAMAV_DB_DIR = os.getenv("CLAMAV_DB_DIR", "/var/lib/clamav")
CLAMSCAN_TIMEOUT = int(os.getenv("CLAMSCAN_TIMEOUT", "30"))

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


def scan_file(filepath: str, extra_db_dir: Optional[str] = None) -> dict:
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

    db_dir = extra_db_dir or CLAMAV_DB_DIR
    if not is_database_available() and not extra_db_dir:
        return {
            "scanned": False, "infected": False, "signature": None,
            "error": "ClamAV virus bazasi topilmadi - 'freshclam' ishga tushirilishi kerak",
        }

    cmd = [CLAMSCAN_BIN, "--no-summary", "-d", db_dir, filepath]

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
