"""
Ma'lumotlar bazasi bilan ishlash uchun markaziy nuqta.
Boshqa modullar (syslog_server, parser, va h.k.) shu yerdan
get_session() ni chaqirib, baza bilan ishlaydi.
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.orm import sessionmaker
from db.models import init_db
from config.settings import DATABASE_URL


def _ensure_sqlite_dir_exists(database_url: str):
    """
    Agar DATABASE_URL SQLite fayl yo'liga ishora qilsa, uning papkasi
    mavjudligini ta'minlaydi. Bu MUHIM: Git bo'sh papkalarni saqlamaydi,
    shuning uchun yangi `git clone`dan keyin `logs/` papkasi mavjud
    bo'lmasligi mumkin - shu holatda SQLite "unable to open database
    file" xatoligini beradi (bu xato aynan shu sabab bilan CI'da
    aniqlangan, lekin doimiy ishlab turgan lokal muhitda "yashiringan" edi).
    """
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
