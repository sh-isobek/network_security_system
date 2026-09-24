"""
Agent Restart Monitor.

Dashboard'dagi "Qayta ulanishga urinish" so'rovlarini kuzatadi (`db/agent_restart.py`):
`AGENT_RESTART_DEADLINE_SECONDS` (standart 60s) ichida agent heartbeat'i kelmagan so'rovni
"failed" qiladi va sababi bilan `high` Alert yaratadi - Notification Engine uni Telegram/Email
orqali adminga yetkazadi. Admin sahifani yopib qo'ygan bo'lsa ham xabar yo'qolmaydi.

Ishga tushirish:
    python -m engine.agent_restart_monitor
    python -m engine.agent_restart_monitor --loop --interval 5
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db import agent_restart

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("agent_restart_monitor")


def run_once() -> int:
    session = get_session()
    try:
        failed = agent_restart.expire_overdue(session)
        session.commit()
        for d in failed:
            logger.warning(f"Agent qayta ulanmadi: {d.hostname or d.ip_address} - {d.agent_restart_message}")
        return len(failed)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval: int):
    logger.info(f"Agent Restart Monitor ishga tushdi (har {interval}s, muddat {agent_restart.DEADLINE_SECONDS}s)")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsiklda xato (davom etadi): {exc}")
        time.sleep(interval)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=5)
    args = ap.parse_args()
    run_loop(args.interval) if args.loop else print(f"failed: {run_once()}")
