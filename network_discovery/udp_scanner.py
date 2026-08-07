"""
UDP Scan - network_discovery paketi.

UDP skanerlash TCP'ga qaraganda tabiatan sekinroq va noaniqroq
(protokolning o'zi "ulanish"ga asoslanmagan) - `nmap -sU` javob
kelmasa "open|filtered" deb belgilaydi (ochiqmi yoki filtrlanganmi
aniq bo'lmaydi). Shuning uchun bu yerda faqat eng keng tarqalgan UDP
xizmatlar (DNS, SNMP, DHCP, NTP) tekshiriladi - to'liq 65535 portni
UDP orqali skanerlash amalda juda uzoq davom etadi.
"""
import logging
import subprocess
from typing import List

from network_discovery.tcp_scanner import OpenPort, _parse_nmap_xml

logger = logging.getLogger("udp_scanner")

COMMON_UDP_PORTS = "53,67,68,69,123,161,162,500,514,1900"


def udp_scan(ip: str, ports: str = COMMON_UDP_PORTS, timeout: int = 120) -> List[OpenPort]:
    """
    MUHIM: UDP scan uchun odatda root/CAP_NET_RAW huquqi kerak
    (nmap raw socket ishlatadi). Agar huquq yetishmasa, nmap xato
    berish o'rniga cheklangan (unprivileged) rejimga o'tadi - natija
    kamroq ishonchli bo'lishi mumkin, lekin xato bermaydi.
    """
    try:
        result = subprocess.run(
            ["nmap", "-sU", "-n", "-p", ports, "-oX", "-", ip],
            capture_output=True, text=True, timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        logger.error(f"udp_scan xatoligi: {exc}")
        return []

    scan_result = _parse_nmap_xml(result.stdout, ip)
    return scan_result.open_ports
