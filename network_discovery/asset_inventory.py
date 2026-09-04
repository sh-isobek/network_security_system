"""
Asset Inventory - network_discovery paketi.

Barcha discovery manbalarini (ARP, ICMP, SNMP, DHCP, AD, UniFi)
birlashtirib, `devices` jadvaliga yozadi/yangilaydi. Bu
`network_discovery/*.py`dagi "topuvchi" modullar bilan
`db/models.Device` orasidagi ko'prik.

Ishga tushirish:
    python -m network_discovery.asset_inventory --cidr 172.16.0.0/22 --interface eth0
"""
import json
import logging
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import get_session
from db.models import Device, utcnow
from network_discovery.arp_scanner import arp_scan
from network_discovery.icmp_scanner import ping_sweep
from network_discovery.mac_vendor import lookup_vendor
from network_discovery.snmp_discovery import snmp_discover
from network_discovery.tcp_scanner import tcp_scan
from network_discovery.unifi_discovery import get_unifi_clients
from network_discovery.ruijie_discovery import get_ruijie_clients

logger = logging.getLogger("asset_inventory")


def _upsert_device(session, ip: str, **fields) -> Device:
    device = session.query(Device).filter(Device.ip_address == ip).first()
    if device is None:
        device = Device(ip_address=ip, source="network_discovery")
        session.add(device)
        session.flush()

    for key, value in fields.items():
        if value is None:
            continue
        if key == "discovery_source" and device.discovery_source:
            # MUHIM: agar qurilma allaqachon boyroq manba orqali topilgan
            # bo'lsa (masalan ARP - MAC bilan), ICMP kabi kambag'alroq
            # manba (faqat "tirik" ekanini biladi) buni "pasaytirmasligi"
            # kerak. discovery_source faqat hali bo'sh bo'lsa yoziladi.
            continue
        setattr(device, key, value)
    device.last_seen = utcnow()
    device.last_discovered_at = utcnow()
    return device


def discover_via_arp(interface: str) -> int:
    """
    ARP scan orqali tarmoqdagi qurilmalarni topib, DB'ga yozadi.
    MAC Vendor lookup ham shu yerda avtomatik qo'llaniladi.
    Qaytaradi: yangilangan/yaratilgan qurilmalar soni.
    """
    results = arp_scan(interface)
    session = get_session()
    count = 0
    try:
        for r in results:
            vendor = lookup_vendor(r.mac)
            _upsert_device(
                session, r.ip,
                mac_address=r.mac,
                vendor=vendor,
                discovery_source="arp_scan",
            )
            count += 1
        session.commit()
        logger.info(f"ARP discovery: {count} ta qurilma yangilandi")
        return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def discover_via_icmp(cidr: str) -> int:
    """ICMP ping sweep orqali tirik IP'larni topib, DB'ga (kamida IP bilan) yozadi."""
    ips = ping_sweep(cidr)
    session = get_session()
    count = 0
    try:
        for ip in ips:
            _upsert_device(session, ip, discovery_source="icmp")
            count += 1
        session.commit()
        logger.info(f"ICMP discovery: {count} ta qurilma yangilandi")
        return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def discover_via_unifi() -> int:
    """
    UniFi Controller'dan (API Key yoki login/parol orqali,
    `network_discovery/unifi_discovery.py`ga qarang) hozir ulangan
    barcha klientlarni olib, DB'ga yozadi. MAC Vendor lookup ham shu
    yerda avtomatik qo'llaniladi. UniFi ma'lumoti (IP+MAC+hostname)
    ko'pincha ARP/ICMP'dan ko'ra ANIQROQ va TO'LIQROQ bo'ladi (Wi-Fi
    orqali ulangan, lekin ARP scan tarmoq segmentidan tashqarida
    bo'lgan qurilmalar ham kiradi) - shuning uchun discovery_source
    ustuvorligi (`_upsert_device`dagi) buni ARP bilan bir xil "boy"
    manba sifatida ko'radi.
    """
    clients = get_unifi_clients()
    session = get_session()
    count = 0
    try:
        for c in clients:
            if not c.ip:
                continue  # IP'siz klientni Device jadvaliga yozib bo'lmaydi (ip_address majburiy)
            vendor = lookup_vendor(c.mac) if c.mac else None
            # MUHIM (halol cheklov): simli ("cable") UniFi klientlari uchun
            # avtomatik bloklash HALI ISHLAMAYDI - SwitchSNMPAdapter
            # `switch_port`ni talab qiladi, UniFi Integration API esa buni
            # bermaydi (faqat uplinkDeviceId - qaysi AP/switch'ga ulangani,
            # aniq port raqami emas). Wi-Fi klientlar uchun (UniFiAdapter)
            # to'liq ishlaydi - bu ko'pchilik holat.
            _upsert_device(
                session, c.ip,
                mac_address=c.mac or None,
                hostname=c.hostname,
                vendor=vendor,
                connection_type="cable" if c.is_wired else "wifi",
                discovery_source="unifi",
            )
            count += 1
        session.commit()
        logger.info(f"UniFi discovery: {count} ta qurilma yangilandi")
        return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def discover_via_ruijie() -> int:
    """
    Ruijie Cloud'dan (App ID/Secret + API Token orqali,
    `network_discovery/ruijie_discovery.py`ga qarang) hozir ulangan
    barcha klientlarni olib, DB'ga yozadi. MAC Vendor lookup ham shu
    yerda avtomatik qo'llaniladi. `discover_via_unifi()` bilan bir xil
    naqsh - Ruijie ma'lumoti ham ARP/ICMP'dan ANIQROQ va TO'LIQROQ
    (Wi-Fi orqali ulangan qurilmalar ham kiradi).
    """
    clients = get_ruijie_clients()
    session = get_session()
    count = 0
    try:
        for c in clients:
            if not c.ip:
                continue  # IP'siz klientni Device jadvaliga yozib bo'lmaydi (ip_address majburiy)
            vendor = lookup_vendor(c.mac) if c.mac else None
            _upsert_device(
                session, c.ip,
                mac_address=c.mac or None,
                hostname=c.hostname,
                vendor=vendor,
                connection_type="cable" if c.is_wired else "wifi",
                discovery_source="ruijie",
            )
            count += 1
        session.commit()
        logger.info(f"Ruijie discovery: {count} ta qurilma yangilandi")
        return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def enrich_with_snmp(ip_list: list, community: str = "public") -> int:
    """Berilgan IP ro'yxati uchun SNMP orqali qo'shimcha ma'lumot (tur, joylashuv) qo'shadi."""
    session = get_session()
    count = 0
    try:
        for ip in ip_list:
            info = snmp_discover(ip, community=community)
            if info is None:
                continue
            _upsert_device(
                session, ip,
                hostname=info.sys_name,
                device_type=info.device_type_guess,
                discovery_source="snmp",
            )
            count += 1
        session.commit()
        logger.info(f"SNMP enrichment: {count} ta qurilma boyitildi")
        return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def enrich_with_tcp_scan(ip_list: list, ports: str = None) -> int:
    """Berilgan IP ro'yxati uchun ochiq portlarni tekshirib, `open_ports` maydonini to'ldiradi."""
    from network_discovery.tcp_scanner import COMMON_PORTS
    session = get_session()
    count = 0
    try:
        for ip in ip_list:
            result = tcp_scan(ip, ports=ports or COMMON_PORTS, detect_service=True)
            if not result.open_ports:
                continue
            ports_json = json.dumps([
                {"port": p.port, "protocol": p.protocol, "service": p.service, "product": p.product}
                for p in result.open_ports
            ])
            device_type = None
            if result.os_guess and "windows" in result.os_guess.lower():
                device_type = "workstation"
            _upsert_device(
                session, ip,
                open_ports=ports_json,
                os_guess=result.os_guess,
                device_type=device_type,
            )
            count += 1
        session.commit()
        logger.info(f"TCP scan enrichment: {count} ta qurilma boyitildi")
        return count
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def full_discovery(cidr: str, interface: str, do_tcp_scan: bool = False, do_snmp: bool = False) -> dict:
    """
    To'liq discovery aylanishi: ARP -> ICMP -> (agar sozlangan bo'lsa)
    UniFi -> (ixtiyoriy) SNMP -> (ixtiyoriy) TCP scan. Bu funksiya CLI
    va boshqa enginelar (masalan davriy discovery) uchun yagona kirish
    nuqtasi.
    """
    stats = {}
    stats["arp"] = discover_via_arp(interface)
    stats["icmp"] = discover_via_icmp(cidr)

    # UniFi faqat UNIFI_CONTROLLER_URL sozlangan bo'lsa ishga tushadi -
    # sozlanmagan bo'lsa get_unifi_clients() baribir bo'sh ro'yxat
    # qaytaradi (xato ko'tarmaydi), shuning uchun bu chaqiruv har doim
    # xavfsiz.
    if os.getenv("UNIFI_CONTROLLER_URL"):
        stats["unifi"] = discover_via_unifi()

    # Ruijie xuddi shu naqsh - faqat RUIJIE_APP_ID sozlangan bo'lsa ishga
    # tushadi, sozlanmagan bo'lsa get_ruijie_clients() baribir bo'sh
    # ro'yxat qaytaradi (xato ko'tarmaydi).
    if os.getenv("RUIJIE_APP_ID"):
        stats["ruijie"] = discover_via_ruijie()

    session = get_session()
    try:
        all_ips = [d.ip_address for d in session.query(Device).filter(Device.discovery_source.in_(["arp_scan", "icmp"])).all()]
    finally:
        session.close()

    if do_snmp and all_ips:
        stats["snmp"] = enrich_with_snmp(all_ips)
    if do_tcp_scan and all_ips:
        stats["tcp_scan"] = enrich_with_tcp_scan(all_ips)

    return stats


if __name__ == "__main__":
    import argparse
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(message)s")

    ap = argparse.ArgumentParser()
    ap.add_argument("--cidr", help="Masalan 172.16.0.0/22 (--unifi-only bilan shart emas)")
    ap.add_argument("--interface", help="Masalan eth0 (--unifi-only bilan shart emas)")
    ap.add_argument("--tcp-scan", action="store_true")
    ap.add_argument("--snmp", action="store_true")
    ap.add_argument("--unifi-only", action="store_true", help="Faqat UniFi Controller'dan (ARP/ICMP'siz)")
    ap.add_argument("--ruijie-only", action="store_true", help="Faqat Ruijie Cloud'dan (ARP/ICMP'siz)")
    args = ap.parse_args()

    if args.unifi_only:
        count = discover_via_unifi()
        print(f"UniFi discovery yakunlandi: {count} ta qurilma")
    elif args.ruijie_only:
        count = discover_via_ruijie()
        print(f"Ruijie discovery yakunlandi: {count} ta qurilma")
    else:
        if not args.cidr or not args.interface:
            ap.error("--cidr va --interface talab qilinadi (yoki --unifi-only ishlating)")
        result = full_discovery(args.cidr, args.interface, do_tcp_scan=args.tcp_scan, do_snmp=args.snmp)
        print(f"Discovery yakunlandi: {result}")
