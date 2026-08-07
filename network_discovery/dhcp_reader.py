"""
DHCP Lease Reader - network_discovery paketi.

Ikkala keng tarqalgan DHCP lease format bilan ishlaydi:
  1. ISC dhcpd (`/var/lib/dhcp/dhcpd.leases`) - Linux DHCP serverlari
     standart formati.
  2. Kerio Control syslog formatidagi DHCP xabarlari (bizning
     `parsers/kerio_parser.py`dagi bilan bir xil regex).
"""
import logging
import re
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

logger = logging.getLogger("dhcp_reader")


@dataclass
class DhcpLease:
    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None
    starts: Optional[datetime] = None
    ends: Optional[datetime] = None
    source: str = "unknown"


# ISC dhcpd.leases formatida bitta lease bloki:
# lease 172.16.1.45 {
#   starts 3 2026/08/07 10:00:00;
#   ends 3 2026/08/07 22:00:00;
#   hardware ethernet aa:bb:cc:dd:ee:ff;
#   client-hostname "ACCOUNTING-PC";
# }
_LEASE_BLOCK_RE = re.compile(r"lease\s+(\d{1,3}(?:\.\d{1,3}){3})\s*\{([^}]*)\}", re.MULTILINE | re.DOTALL)
_MAC_RE = re.compile(r"hardware ethernet\s+([0-9a-fA-F:]{17})")
_HOSTNAME_RE = re.compile(r'client-hostname\s+"([^"]*)"')
_STARTS_RE = re.compile(r"starts\s+\d\s+([\d/]+\s[\d:]+)")
_ENDS_RE = re.compile(r"ends\s+\d\s+([\d/]+\s[\d:]+)")


def parse_isc_dhcpd_leases(filepath: str) -> List[DhcpLease]:
    """ISC dhcpd.leases faylini o'qiydi. Bir xil IP uchun bir nechta
    lease bloki bo'lishi mumkin (tarix) - eng oxirgisi (fayldagi
    oxirgi) ishlatiladi, chunki bu eng so'nggi holat."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            content = f.read()
    except OSError as exc:
        logger.error(f"Lease faylini o'qib bo'lmadi: {exc}")
        return []

    leases_by_ip = {}
    for match in _LEASE_BLOCK_RE.finditer(content):
        ip, block = match.groups()
        mac_m = _MAC_RE.search(block)
        hostname_m = _HOSTNAME_RE.search(block)
        starts_m = _STARTS_RE.search(block)
        ends_m = _ENDS_RE.search(block)

        lease = DhcpLease(
            ip=ip,
            mac=mac_m.group(1).upper() if mac_m else None,
            hostname=hostname_m.group(1) if hostname_m else None,
            starts=_parse_isc_datetime(starts_m.group(1)) if starts_m else None,
            ends=_parse_isc_datetime(ends_m.group(1)) if ends_m else None,
            source="isc_dhcpd",
        )
        leases_by_ip[ip] = lease  # oxirgisi ustidan yozadi - fayl xronologik tartibda

    logger.info(f"ISC dhcpd.leases: {len(leases_by_ip)} ta noyob IP topildi")
    return list(leases_by_ip.values())


def _parse_isc_datetime(value: str) -> Optional[datetime]:
    try:
        return datetime.strptime(value, "%Y/%m/%d %H:%M:%S")
    except ValueError:
        return None


# Kerio syslog formatidagi DHCP xabari (parsers/kerio_parser.py bilan bir xil)
_KERIO_DHCP_RE = re.compile(
    r"DHCP:\s*Lease\s+granted\s+to\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"MAC=(?P<mac>[0-9A-Fa-f:]{17})"
    r"(?:\s+HOST=(?P<host>\S+))?"
)


def parse_kerio_dhcp_log(filepath: str) -> List[DhcpLease]:
    """Kerio Control'dan eksport qilingan/syslog orqali yozilgan DHCP loglarini o'qiydi."""
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError as exc:
        logger.error(f"Kerio DHCP log faylini o'qib bo'lmadi: {exc}")
        return []

    leases_by_ip = {}
    for line in lines:
        m = _KERIO_DHCP_RE.search(line)
        if m:
            leases_by_ip[m.group("ip")] = DhcpLease(
                ip=m.group("ip"),
                mac=m.group("mac").upper(),
                hostname=m.group("host"),
                source="kerio",
            )

    logger.info(f"Kerio DHCP log: {len(leases_by_ip)} ta noyob IP topildi")
    return list(leases_by_ip.values())
