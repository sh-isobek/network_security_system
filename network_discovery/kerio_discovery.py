"""
Kerio Discovery - network_discovery paketi.

Loyiha talabiga ko'ra (foydalanuvchi qarori) Kerio Control FAQAT DHCP
manba sifatida ishlatiladi (bloklash yoki boshqa maqsadlarda emas).
Bu modul `dhcp_reader.py`dagi Kerio parser'ini "discovery" interfeysi
sifatida taqdim etadi - `asset_inventory.py` boshqa discovery
manbalari (ARP, SNMP) bilan bir xil formatda ishlata olishi uchun.
"""
import logging
from typing import List

from network_discovery.dhcp_reader import DhcpLease, parse_kerio_dhcp_log

logger = logging.getLogger("kerio_discovery")


def discover_from_kerio_log(log_filepath: str) -> List[DhcpLease]:
    """
    Kerio Control syslog fayli (yoki NXLog orqali kollektorimizga
    kelgan loglarning fayl nusxasi)dan qurilmalar ro'yxatini oladi.

    Eslatma: real vaqtli oqim uchun `collectors/syslog_server.py`
    allaqachon Kerio DHCP xabarlarini qabul qilib, `parsers/
    kerio_parser.py` orqali bazaga yozadi - bu funksiya asosan
    **fayl-asosida** (masalan eksport qilingan log arxivi) bir martalik
    inventarizatsiya uchun foydali.
    """
    leases = parse_kerio_dhcp_log(log_filepath)
    logger.info(f"Kerio Discovery: {len(leases)} ta qurilma topildi")
    return leases
