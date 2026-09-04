"""
Ruijie Sync Loop - network_discovery paketi.

`network_discovery/unifi_sync_loop.py` bilan bir xil naqsh - Ruijie
Cloud discovery ham (`ruijie_discovery.py`) shunchaki HTTPS API
so'rovi, na host tarmoq, na maxsus huquq talab qilmaydi. Shuning uchun
bu ham ALOHIDA, standart Docker tarmog'ida, HECH QANDAY profildan
tashqarida ishlaydigan davriy sikl sifatida ajratilgan - `docker
compose up -d` bilan avtomatik ishga tushishi uchun.

Ishga tushirish:
    python -m network_discovery.ruijie_sync_loop --once
    python -m network_discovery.ruijie_sync_loop --loop --interval 300
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ruijie_sync_loop")


def run_once() -> int:
    """
    Bitta sinxronizatsiya siklini bajaradi. RUIJIE_APP_ID sozlanmagan
    bo'lsa, jim ravishda 0 qaytaradi (xato emas - bu xizmat Ruijie
    sozlanmagan muhitlarda ham zararsiz ishlab turishi uchun ataylab
    shunday).
    """
    if not os.getenv("RUIJIE_APP_ID"):
        logger.debug("RUIJIE_APP_ID sozlanmagan - sinxronizatsiya o'tkazib yuborildi")
        return 0

    from network_discovery.asset_inventory import discover_via_ruijie
    return discover_via_ruijie()


def run_loop(interval_seconds: int = 300):
    logger.info(f"Ruijie sync tsiklda ishga tushdi (har {interval_seconds}s)")
    while True:
        try:
            n = run_once()
            if n:
                logger.info(f"Ruijie sync: {n} ta qurilma yangilandi")
        except Exception as exc:
            logger.error(f"Ruijie sync tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=int(os.getenv("RUIJIE_POLL_INTERVAL", "300")))
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        print(f"Ruijie sync yakunlandi: {n} ta qurilma yangilandi")
