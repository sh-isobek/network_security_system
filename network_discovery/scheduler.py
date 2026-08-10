"""
Scheduled + Differential Scanning - network_discovery paketi.

"Differensial" skanerlash - har safar to'liq holatni emas, balki
OLDINGI holat bilan solishtirganda nima O'ZGARGANINI aniqlaydi:
  - Yangi qurilma paydo bo'ldi -> "discovered"
  - Avval faol bo'lgan qurilma endi javob bermayapti -> "disappeared"
  - Avval "yo'qolgan" deb belgilangan qurilma qayta paydo bo'ldi -> "reappeared"

Bu o'zgarishlar `device_history` jadvaliga yoziladi - shu orqali
"qachon qo'shildi, qachon yo'qoldi" degan savolga javob berish mumkin
(Asset History).

Ishga tushirish:
    python -m network_discovery.scheduler --cidr 172.16.0.0/22 --interface eth0 --once
    python -m network_discovery.scheduler --cidr 172.16.0.0/22 --interface eth0 --loop --interval 3600
"""
import argparse
import logging
import os
import sys
import time
from datetime import timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import get_session
from db.models import Device, DeviceHistory, utcnow
from network_discovery.arp_scanner import arp_scan
from network_discovery.icmp_scanner import ping_sweep
from network_discovery.mac_vendor import lookup_vendor

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("discovery_scheduler")

# Bu vaqtdan ko'proq "ko'rinmagan" qurilma "yo'qolgan" deb hisoblanadi
MISSING_THRESHOLD_HOURS = int(os.getenv("DISCOVERY_MISSING_THRESHOLD_HOURS", "24"))


def run_differential_scan(cidr: str, interface: str) -> dict:
    """
    Bitta differensial skanerlash siklini bajaradi. Qaytaradi:
    {"discovered": [...], "disappeared": [...], "reappeared": [...]}
    """
    arp_results = arp_scan(interface)
    icmp_ips = set(ping_sweep(cidr))
    live_ips = {r.ip for r in arp_results} | icmp_ips
    arp_by_ip = {r.ip: r for r in arp_results}

    session = get_session()
    changes = {"discovered": [], "disappeared": [], "reappeared": []}

    try:
        # MUHIM: `ip_address` bazada GLOBAL unique (boshqa subsystemlar -
        # masalan parser_engine - ham shu ustunga yozadi, discovery_source'dan
        # qat'iy nazar). Shuning uchun "yangi qurilmami" tekshiruvini FAQAT
        # discovery_source'ga ega qurilmalar bilan emas, BARCHA qurilmalar
        # bilan solishtirib qilish kerak - aks holda boshqa manba orqali
        # allaqachon mavjud IP uchun INSERT to'qnashadi (UNIQUE constraint).
        all_existing = {d.ip_address: d for d in session.query(Device).all()}
        known_devices = {
            ip: d for ip, d in all_existing.items() if d.discovery_source is not None
        }

        now = utcnow()
        missing_cutoff = now - timedelta(hours=MISSING_THRESHOLD_HOURS)

        # 1) Yangi topilgan yoki qayta paydo bo'lgan qurilmalar
        for ip in live_ips:
            device = known_devices.get(ip)
            existing_any_source = all_existing.get(ip)

            if device is None and existing_any_source is None:
                # Butunlay yangi qurilma - bazada umuman yo'q
                new_device = Device(
                    ip_address=ip,
                    mac_address=arp_by_ip[ip].mac if ip in arp_by_ip else None,
                    vendor=lookup_vendor(arp_by_ip[ip].mac) if ip in arp_by_ip else None,
                    discovery_source="arp_scan" if ip in arp_by_ip else "icmp",
                    last_seen=now, last_discovered_at=now,
                )
                session.add(new_device)
                session.add(DeviceHistory(device_ip=ip, event_type="discovered", details="Birinchi marta topildi"))
                changes["discovered"].append(ip)

            elif device is None and existing_any_source is not None:
                # Boshqa subsystem (masalan syslog parser) orqali allaqachon
                # mavjud IP - discovery_source'ni endi to'ldiramiz (birinchi
                # marta network discovery orqali "ko'rildi"), lekin YANGI
                # qator qo'shmaymiz
                existing_any_source.discovery_source = "arp_scan" if ip in arp_by_ip else "icmp"
                if ip in arp_by_ip:
                    existing_any_source.mac_address = arp_by_ip[ip].mac
                    existing_any_source.vendor = lookup_vendor(arp_by_ip[ip].mac)
                existing_any_source.last_seen = now
                existing_any_source.last_discovered_at = now

            elif device.last_discovered_at and device.last_discovered_at < missing_cutoff:
                # Avval "yo'qolgan" deb hisoblanardi (uzoq vaqt ko'rinmagan), endi qayta topildi
                device.last_seen = now
                device.last_discovered_at = now
                session.add(DeviceHistory(device_ip=ip, event_type="reappeared",
                                            details=f"{MISSING_THRESHOLD_HOURS} soatdan ko'p vaqt yo'qolgandan keyin qayta topildi"))
                changes["reappeared"].append(ip)

            else:
                # Oddiy "hali ham faol" - tarix yozuvi kerak emas, faqat vaqtni yangilaymiz
                device.last_seen = now
                device.last_discovered_at = now

        # 2) Yo'qolgan qurilmalar (bazada bor, lekin joriy skanerlashda topilmadi
        #    VA yaqinda "yo'qolgan" deb allaqachon belgilanmagan)
        for ip, device in known_devices.items():
            if ip in live_ips:
                continue
            if device.last_discovered_at and device.last_discovered_at >= missing_cutoff:
                continue  # hali chegaradan o'tmagan - hozircha "yo'qolgan" deb belgilamaymiz

            already_marked = (
                session.query(DeviceHistory)
                .filter(DeviceHistory.device_ip == ip, DeviceHistory.event_type == "disappeared")
                .order_by(DeviceHistory.timestamp.desc())
                .first()
            )
            # Agar oxirgi tarix yozuvi "disappeared" bo'lsa va undan keyin
            # "reappeared" bo'lmagan bo'lsa - qayta yozmaymiz (bir marta yetarli)
            if already_marked and already_marked.timestamp > (device.last_discovered_at or now):
                continue

            session.add(DeviceHistory(device_ip=ip, event_type="disappeared",
                                        details=f"So'nggi {MISSING_THRESHOLD_HOURS} soatda topilmadi"))
            changes["disappeared"].append(ip)

        session.commit()
        logger.info(
            f"Differensial scan: {len(changes['discovered'])} yangi, "
            f"{len(changes['disappeared'])} yo'qolgan, {len(changes['reappeared'])} qayta paydo bo'lgan"
        )
        return changes

    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(cidr: str, interface: str, interval_seconds: int = 3600):
    logger.info(f"Scheduled discovery tsiklda ishga tushdi (har {interval_seconds}s)")
    while True:
        try:
            run_differential_scan(cidr, interface)
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--cidr", required=True)
    ap.add_argument("--interface", required=True)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=3600)
    args = ap.parse_args()

    if args.loop:
        run_loop(args.cidr, args.interface, args.interval)
    else:
        result = run_differential_scan(args.cidr, args.interface)
        print(f"Natija: {result}")
