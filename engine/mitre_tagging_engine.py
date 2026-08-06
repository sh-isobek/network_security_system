"""
MITRE Tagging Engine.

`alerts` jadvalidan hali MITRE bilan belgilanmagan (mitre_technique_id
IS NULL) yozuvlarni oladi, `intel/mitre_attack.py` orqali tasniflaydi
va texnika/taktika ma'lumotlarini yozadi.

Bu alohida, mustaqil bosqich sifatida ishlaydi (boshqa enginelarga
bog'liq emas) - shuning uchun istalgan vaqtda orqaga qaytib, eski
alertlarni ham qayta belgilash mumkin (masalan mapping qoidalari
yangilangach: --retag bilan).

Ishga tushirish:
    python -m engine.mitre_tagging_engine
    python -m engine.mitre_tagging_engine --loop
    python -m engine.mitre_tagging_engine --retag   # barcha alertlarni qayta belgilaydi
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import Alert
from intel.mitre_attack import classify

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("mitre_tagging_engine")

BATCH_SIZE = 200


def tag_one(alert: Alert):
    mapping = classify(alert.reason or "")
    alert.mitre_technique_id = mapping.technique_id
    alert.mitre_technique_name = mapping.technique_name
    alert.mitre_tactic = mapping.tactic


def run_once(retag: bool = False):
    session = get_session()
    try:
        query = session.query(Alert)
        if not retag:
            query = query.filter(Alert.mitre_technique_id.is_(None))
        pending = query.limit(BATCH_SIZE).all()

        if not pending:
            return 0

        for alert in pending:
            tag_one(alert)

        session.commit()
        logger.info(f"{len(pending)} ta alert MITRE ATT&CK bilan belgilandi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = 15):
    logger.info("MITRE tagging engine tsiklda ishga tushdi")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=15)
    ap.add_argument("--retag", action="store_true", help="Barcha alertlarni (belgilanganlarni ham) qayta tasniflaydi")
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once(retag=args.retag)
        logger.info(f"Yakunlandi: {n} ta alert belgilandi")
