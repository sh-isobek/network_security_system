"""
Davomat subtizimi uchun baza bilan ishlash markazi.

`db/database.py` bilan bir xil pattern, lekin `attendance/models.py`
ning mustaqil `AttnBase`sidan foydalanadi. Bir xil `DATABASE_URL`
(config/settings.py) ishlatiladi - SQLite (dev/test) va PostgreSQL
(production) o'rtasida kod o'zgarmaydi.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import sessionmaker

from attendance.models import init_db
from config.settings import DATABASE_URL


def _ensure_sqlite_dir_exists(database_url: str):
    if not database_url.startswith("sqlite:///"):
        return
    db_path = database_url.replace("sqlite:///", "", 1)
    db_dir = os.path.dirname(db_path)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)


_ensure_sqlite_dir_exists(DATABASE_URL)
_engine = init_db(DATABASE_URL)
SessionLocal = sessionmaker(bind=_engine)


def get_session():
    """Har chaqirilganda yangi session qaytaradi. Ishlatib bo'lgach .close() qiling."""
    return SessionLocal()
