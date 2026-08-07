"""
ARP Scan - network_discovery paketi.

`arp-scan` CLI vositasi orqali ishlaydi. ICMP'dan farqli, ARP odatda
firewall tomonidan bloklanmaydi (chunki L2 darajasida ishlaydi, lokal
tarmoqdan tashqariga chiqmaydi) - shuning uchun bu **eng ishonchli**
"tirik host" aniqlash usuli hisoblanadi.

Real test: `192.0.2.0/24` tarmog'ida haqiqiy host (`192.0.2.1`) va
uning haqiqiy MAC manzili to'g'ri aniqlangan.
"""
import logging
import re
import subprocess
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger("arp_scanner")


@dataclass
class ArpResult:
    ip: str
    mac: str
    vendor_hint: Optional[str] = None  # arp-scan ba'zan o'zi taxminiy vendor beradi


def arp_scan(interface: str, target: Optional[str] = None, timeout: int = 60) -> List[ArpResult]:
    """
    Berilgan interfeys orqali ARP scan qiladi.
    `target` berilmasa, interfeysning "local network"i (masalan
    `--localnet`) skanerlanadi.
    """
    cmd = ["arp-scan", "-I", interface, "--retry=2"]
    cmd.append(target if target else "--localnet")

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        logger.error("arp-scan topilmadi - 'apt install arp-scan' bilan o'rnating")
        return []
    except subprocess.TimeoutExpired:
        logger.error(f"arp_scan timeout ({timeout}s)")
        return []

    results = []
    seen = set()
    # Namuna qator: "192.0.2.1\t02:fc:00:00:00:05\t(Unknown: locally administered)"
    for line in result.stdout.splitlines():
        m = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)$", line.strip())
        if m:
            ip, mac, vendor = m.groups()
            mac = mac.upper()
            if (ip, mac) in seen:
                continue  # arp-scan ba'zan bir xil javobni "(DUP: N)" bilan bir necha marta ko'rsatadi
            seen.add((ip, mac))
            vendor_clean = re.sub(r"\s*\(DUP:\s*\d+\)?\s*$", "", vendor).strip("() ")
            results.append(ArpResult(ip=ip, mac=mac, vendor_hint=vendor_clean or None))

    logger.info(f"ARP scan ({interface}): {len(results)} ta javob")
    return results
