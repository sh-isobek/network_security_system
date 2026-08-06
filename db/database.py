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

_engine = init_db(DATABASE_URL)
SessionLocal = sessionmaker(bind=_engine)


def get_session():
    """Har chaqirilganda yangi session qaytaradi. Ishlatib bo'lgach .close() qiling."""
    return SessionLocal()
