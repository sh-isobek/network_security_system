"""
IPv6 Discovery - network_discovery paketi.

ICMPv6 Echo (ping sweep) va NDP (Neighbor Discovery Protocol - IPv6'da
ARP'ning o'rnini bosadi) orqali ishlaydi.

HALOL CHEKLOV: bu modul ushbu loyiha tayyorlangan sandbox muhitida
sinalmagan - IPv6 butunlay o'chirilgan edi (`ping -6` "Address family
not supported by protocol" xatoligini berdi, `ip -6 addr` hech qanday
manzil ko'rsatmadi). Kod IPv6/NDP standart RFC'lariga (RFC 4861) va
`nmap`ning IPv6 hujjatlashtirilgan xatti-harakatiga qat'iy mos yozilgan,
lekin haqiqiy IPv6 tarmog'ida hali tekshirilmagan - production'ga
joylashtirishdan oldin IPv6 mavjud muhitda qayta tekshirish tavsiya
etiladi.
"""
import logging
import re
import subprocess
from typing import List

logger = logging.getLogger("ipv6_discovery")


def ipv6_ping_sweep(cidr6: str, interface: str, timeout: int = 60) -> List[str]:
    """
    IPv6 tarmog'ida ICMPv6 ping sweep. IPv6'da to'liq subnet'ni
    (masalan /64, 2^64 manzil) skanerlash amalda mumkin emas - shuning
    uchun bu funksiya faqat kichik, aniq belgilangan diapazonlar
    (masalan /120 yoki undan kichik) uchun ishlatilishi kerak.
    Katta IPv6 tarmoqlarda NDP orqali "allaqachon ma'lum" qo'shnilarni
    olish (`ipv6_ndp_neighbors()`) ancha amaliy yondashuv.
    """
    try:
        result = subprocess.run(
            ["nmap", "-6", "-sn", "-n", "-e", interface, cidr6],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.error("nmap topilmadi")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"ipv6_ping_sweep timeout ({timeout}s)")
        return []

    if result.returncode != 0:
        logger.error(f"nmap -6 xatoligi: {result.stderr}")
        return []

    ips = re.findall(r"Nmap scan report for (?:\S+ \()?([0-9a-fA-F:]+)\)?", result.stdout)
    logger.info(f"IPv6 ping sweep ({cidr6}): {len(ips)} ta tirik host")
    return ips


def ipv6_ndp_neighbors(interface: str) -> List[dict]:
    """
    NDP jadvalini o'qiydi (`ip -6 neigh show`) - bu ARP jadvaliga
    o'xshaydi, lekin IPv6 uchun. Faqat interfeys allaqachon "gaplashgan"
    (masalan ma'lumot almashgan) qo'shnilarni ko'rsatadi - faol scan
    emas, passiv kuzatuv.
    """
    try:
        result = subprocess.run(
            ["ip", "-6", "neigh", "show", "dev", interface],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    neighbors = []
    for line in result.stdout.splitlines():
        # Namuna qator: "fe80::1 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
        m = re.match(r"^([0-9a-fA-F:]+)\s+lladdr\s+([0-9a-fA-F:]{17})\s+(\w+)", line.strip())
        if m:
            ip6, mac, state = m.groups()
            neighbors.append({"ipv6": ip6, "mac": mac.upper(), "state": state})

    logger.info(f"NDP neighbors ({interface}): {len(neighbors)} ta topildi")
    return neighbors
