"""
Kerio Control Connection log parser.

Kerio Control DHCP/Connection loglarini quyidagi (odatiy) formatda yuboradi:
    <134>Jul 30 13:01:58 KERIO-GW Connection: SRC=172.16.1.45 DST=8.8.8.8 DPT=443 PROTO=TCP ACTION=Permit

Eslatma: loyiha talabiga ko'ra Kerio Control FAQAT DHCP manba sifatida
ishlatiladi. Shuning uchun bu parser Kerio'dan faqat IP/MAC/hostname
bog'lash (DHCP lease) ma'lumotini oladi, connection/filter loglarini
"xavfni aniqlash" uchun ishlatmaydi - ular Suricata (keyingi bosqich)
zimmasida bo'ladi. Hozircha ikkala format ham qo'llab-quvvatlanadi,
chunki DHCP lease log formati ham shunga o'xshash key=value uslubida keladi.
"""
import re
from typing import Optional

from parsers.base import BaseParser, ParsedEvent

# Namuna: SRC=172.16.1.45 DST=8.8.8.8 DPT=443 PROTO=TCP ACTION=Permit
_CONNECTION_RE = re.compile(
    r"SRC=(?P<src>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"DST=(?P<dst>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"DPT=(?P<port>\d+)\s+"
    r"PROTO=(?P<proto>\w+)"
)

# Namuna DHCP lease log: DHCP: Lease granted to 172.16.1.45 MAC=AA:BB:CC:DD:EE:FF HOST=ACCOUNTING-PC
_DHCP_RE = re.compile(
    r"DHCP:\s*Lease\s+granted\s+to\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"MAC=(?P<mac>[0-9A-Fa-f:]{17})"
    r"(?:\s+HOST=(?P<host>\S+))?"
)


class KerioConnectionParser(BaseParser):
    name = "kerio_connection"

    def can_parse(self, raw_message: str) -> bool:
        return "SRC=" in raw_message and "DST=" in raw_message

    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        m = _CONNECTION_RE.search(raw_message)
        if not m:
            return None
        return ParsedEvent(
            source_ip=m.group("src"),
            dest_ip=m.group("dst"),
            dest_domain=None,
            dest_port=int(m.group("port")),
            protocol=m.group("proto").upper(),
            event_type="connection",
        )


class KerioDHCPParser(BaseParser):
    """Faqat DHCP lease (IP-MAC-Hostname) ma'lumotini ajratib oladi."""
    name = "kerio_dhcp"

    def can_parse(self, raw_message: str) -> bool:
        return raw_message.strip().startswith("DHCP:") or "Lease granted" in raw_message

    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        m = _DHCP_RE.search(raw_message)
        if not m:
            return None
        return ParsedEvent(
            source_ip=m.group("ip"),
            mac_address=m.group("mac").upper(),
            hostname=m.group("host"),
            event_type="dhcp_lease",
        )
