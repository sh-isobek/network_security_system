"""
ICMP Ping Sweep - network_discovery paketi.

`nmap -sn` (ping sweep, port skanerlashsiz) orqali ishlaydi - real
ICMP paketlarni yuboradi va javob berganlarni "tirik" deb belgilaydi.

Real test: ushbu loyiha tayyorlangan sandbox muhitida `192.0.2.0/24`
tarmog'ida ishga tushirilib, haqiqiy 2 ta host (gateway va o'zi)
to'g'ri aniqlangan.
"""
import logging
import re
import subprocess
from typing import List

logger = logging.getLogger("icmp_scanner")


def ping_sweep(cidr: str, timeout: int = 60) -> List[str]:
    """
    Berilgan CIDR (masalan "172.16.0.0/22") ichidagi tirik IP'larni
    ICMP orqali topadi. Javob bermagan (ICMP bloklangan) qurilmalar
    aniqlanmasligi mumkin - bu holatda ARP scan (`arp_scanner.py`)
    ko'proq ishonchli, chunki lokal tarmoqda ARP odatda bloklanmaydi.
    """
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-n", cidr],
            capture_output=True, text=True, timeout=timeout,
        )
    except FileNotFoundError:
        logger.error("nmap topilmadi - 'apt install nmap' bilan o'rnating")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"ping_sweep timeout ({timeout}s): {cidr}")
        return []

    if result.returncode != 0:
        logger.error(f"nmap xatoligi: {result.stderr}")
        return []

    ips = re.findall(r"Nmap scan report for (?:\S+ \()?(\d{1,3}(?:\.\d{1,3}){3})\)?", result.stdout)
    logger.info(f"Ping sweep ({cidr}): {len(ips)} ta tirik host topildi")
    return ips


def ping_single(ip: str, timeout: int = 3) -> bool:
    """Bitta IP'ga ICMP ping yuboradi, javob bersa True."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), ip],
            capture_output=True, text=True, timeout=timeout + 2,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False
