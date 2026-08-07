"""
Backup/Restore/Snapshot - yangi TZ 19-bo'lim.

Ikkala baza turini (SQLite va PostgreSQL) qo'llab-quvvatlaydi -
`DATABASE_URL`dan avtomatik aniqlanadi.

Ishga tushirish:
    python -m backup.backup_manager --backup
    python -m backup.backup_manager --list
    python -m backup.backup_manager --restore /path/to/backup_file
"""
import argparse
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import DATABASE_URL
from db.models import utcnow

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("backup_manager")

BACKUP_DIR = os.getenv("BACKUP_DIR", "./backups")


def _db_type() -> str:
    return "postgres" if DATABASE_URL.startswith("postgresql://") else "sqlite"


def _sqlite_path() -> str:
    return DATABASE_URL.replace("sqlite:///", "", 1)


def backup_sqlite(output_dir: str) -> str:
    """
    SQLite bazasini xavfsiz nusxalaydi - `sqlite3`ning o'z BACKUP API'si
    orqali (oddiy fayl nusxalash o'rniga), chunki baza yozish paytida
    ham izchil (consistent) nusxa olinishini kafolatlaydi.
    """
    os.makedirs(output_dir, exist_ok=True)
    src_path = _sqlite_path()
    timestamp = utcnow().strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(output_dir, f"backup_{timestamp}.sqlite3")

    src_conn = sqlite3.connect(src_path)
    dest_conn = sqlite3.connect(dest_path)
    with dest_conn:
        src_conn.backup(dest_conn)
    src_conn.close()
    dest_conn.close()

    logger.info(f"SQLite backup yaratildi: {dest_path}")
    return dest_path


def restore_sqlite(backup_path: str) -> bool:
    if not os.path.isfile(backup_path):
        logger.error(f"Backup fayl topilmadi: {backup_path}")
        return False

    dest_path = _sqlite_path()

    # Xavfsizlik: joriy bazani ustidan yozishdan oldin, uni ham
    # zaxiralab qo'yamiz (agar restore noto'g'ri bo'lsa, orqaga qaytish uchun)
    if os.path.isfile(dest_path):
        safety_copy = dest_path + ".before_restore"
        shutil.copy2(dest_path, safety_copy)
        logger.info(f"Joriy baza {safety_copy}ga zaxiralandi (xavfsizlik nusxasi)")

    src_conn = sqlite3.connect(backup_path)
    dest_conn = sqlite3.connect(dest_path)
    with dest_conn:
        src_conn.backup(dest_conn)
    src_conn.close()
    dest_conn.close()

    logger.info(f"SQLite tiklandi: {backup_path} -> {dest_path}")
    return True


def backup_postgres(output_dir: str) -> str:
    os.makedirs(output_dir, exist_ok=True)
    parsed = urlparse(DATABASE_URL)
    timestamp = utcnow().strftime("%Y%m%d_%H%M%S")
    dest_path = os.path.join(output_dir, f"backup_{timestamp}.sql")

    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = parsed.password

    cmd = [
        "pg_dump",
        "-h", parsed.hostname or "localhost",
        "-p", str(parsed.port or 5432),
        "-U", parsed.username or "postgres",
        "-d", parsed.path.lstrip("/"),
        "-f", dest_path,
        "--no-password",
        "--clean", "--if-exists",   # DROP ... IF EXISTS qo'shadi - restore
                                       # vaqtida mavjud jadvallar bilan
                                       # to'qnashmasligi uchun (aks holda
                                       # CREATE TABLE xatosi butun
                                       # tranzaksiyani bekor qiladi va undan
                                       # keyingi COPY ma'lumot buyruqlari
                                       # ham jim e'tiborsiz qoldiriladi -
                                       # bu real testda aniqlangan xato edi)
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError(f"pg_dump muvaffaqiyatsiz: {result.stderr}")

    logger.info(f"PostgreSQL backup yaratildi: {dest_path}")
    return dest_path


def restore_postgres(backup_path: str) -> bool:
    if not os.path.isfile(backup_path):
        logger.error(f"Backup fayl topilmadi: {backup_path}")
        return False

    parsed = urlparse(DATABASE_URL)
    env = os.environ.copy()
    if parsed.password:
        env["PGPASSWORD"] = parsed.password

    cmd = [
        "psql",
        "-h", parsed.hostname or "localhost",
        "-p", str(parsed.port or 5432),
        "-U", parsed.username or "postgres",
        "-d", parsed.path.lstrip("/"),
        "-v", "ON_ERROR_STOP=1",   # birinchi xatoda to'xtaydi (jim tranzaksiya
                                      # bekor qilinishi va ma'lumotning sezilmay
                                      # yo'qolishi o'rniga aniq xato beradi)
        "-f", backup_path,
    ]
    result = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        logger.error(f"psql restore xatoligi: {result.stderr}")
        return False

    logger.info(f"PostgreSQL tiklandi: {backup_path}")
    return True


def create_backup(output_dir: str = BACKUP_DIR) -> str:
    if _db_type() == "postgres":
        return backup_postgres(output_dir)
    return backup_sqlite(output_dir)


def restore_backup(backup_path: str) -> bool:
    if _db_type() == "postgres":
        return restore_postgres(backup_path)
    return restore_sqlite(backup_path)


def list_backups(backup_dir: str = BACKUP_DIR) -> list:
    if not os.path.isdir(backup_dir):
        return []
    files = sorted(
        [f for f in os.listdir(backup_dir) if f.startswith("backup_")],
        reverse=True,
    )
    return [os.path.join(backup_dir, f) for f in files]


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--backup", action="store_true")
    ap.add_argument("--restore", metavar="FILE")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--output-dir", default=BACKUP_DIR)
    args = ap.parse_args()

    if args.backup:
        path = create_backup(args.output_dir)
        print(f"Backup yaratildi: {path}")
    elif args.restore:
        ok = restore_backup(args.restore)
        print("Muvaffaqiyatli tiklandi" if ok else "Tiklashda xatolik")
    elif args.list:
        for b in list_backups(args.output_dir):
            print(b)
    else:
        print("--backup, --restore FILE yoki --list ishlating")
