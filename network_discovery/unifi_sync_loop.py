"""
UniFi Sync Loop - network_discovery paketi.

`scheduler.py` (ARP/ICMP differensial scan) `network_mode: host` va
NET_ADMIN/NET_RAW huquqini talab qiladi (haqiqiy L2 tarmoq skanerlash
uchun) - shuning uchun Docker Compose'da `--profile discovery` bilan
ixtiyoriy qilib qo'yilgan.

UniFi discovery esa BUTUNLAY BOSHQACHA: bu shunchaki UniFi
Controller'ga HTTPS API so'rovi (`network_discovery/unifi_discovery.
py`) - na host tarmoq, na maxsus huquq talab qilmaydi. Shuning uchun
bu ALOHIDA, standart Docker tarmog'ida, HECH QANDAY profildan
tashqarida ishlaydigan davriy sikl sifatida ajratilgan - `docker
compose up -d` bilan avtomatik ishga tushishi uchun.

Ishga tushirish:
    python -m network_discovery.unifi_sync_loop --once
    python -m network_discovery.unifi_sync_loop --loop --interval 300
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("unifi_sync_loop")


def run_once() -> int:
    """
    Bitta sinxronizatsiya siklini bajaradi. UNIFI_CONTROLLER_URL
    sozlanmagan bo'lsa, jim ravishda 0 qaytaradi (xato emas - bu
    xizmat UniFi sozlanmagan muhitlarda ham zararsiz ishlab turishi
    uchun ataylab shunday).
    """
    if not os.getenv("UNIFI_CONTROLLER_URL"):
        logger.debug("UNIFI_CONTROLLER_URL sozlanmagan - sinxronizatsiya o'tkazib yuborildi")
        return 0

    from network_discovery.asset_inventory import discover_via_unifi
    return discover_via_unifi()


def run_loop(interval_seconds: int = 300):
    logger.info(f"UniFi sync tsiklda ishga tushdi (har {interval_seconds}s)")
    while True:
        try:
            n = run_once()
            if n:
                logger.info(f"UniFi sync: {n} ta qurilma yangilandi")
        except Exception as exc:
            logger.error(f"UniFi sync tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=int(os.getenv("UNIFI_POLL_INTERVAL", "300")))
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        print(f"UniFi sync yakunlandi: {n} ta qurilma yangilandi")
