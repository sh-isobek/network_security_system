"""
LLDP Mapper - network_discovery paketi.

LLDP (Link Layer Discovery Protocol) - switch/router'lar o'zlari
haqida (nomi, port, model) ma'lumotni har necha soniyada L2 multicast
frame orqali e'lon qilib turadi (standart IEEE 802.1AB). Bu orqali
"qaysi qurilma qaysi switch portiga ulangan" ma'lumotini olish mumkin
- bu `topology_builder.py` uchun asosiy manba.

`scapy`ning `sniff()` funksiyasi orqali ishlaydi - L2 capture uchun
CAP_NET_RAW (yoki root) huquqi va mos tarmoq interfeysi kerak.
"""
import logging
from dataclasses import dataclass
from typing import List, Optional

from scapy.all import sniff, Ether
from scapy.contrib.lldp import LLDPDU, LLDPDUSystemName, LLDPDUPortDescription, LLDPDUChassisID, LLDPDUManagementAddress

logger = logging.getLogger("lldp_mapper")

LLDP_MULTICAST_MAC = "01:80:c2:00:00:0e"


@dataclass
class LldpNeighbor:
    chassis_id: Optional[str] = None
    system_name: Optional[str] = None
    port_description: Optional[str] = None
    management_address: Optional[str] = None
    received_on_interface: str = ""


def _parse_lldp_packet(packet, interface: str) -> Optional[LldpNeighbor]:
    if not packet.haslayer(LLDPDU):
        return None

    neighbor = LldpNeighbor(received_on_interface=interface)

    if packet.haslayer(LLDPDUChassisID):
        chassis = packet[LLDPDUChassisID]
        try:
            neighbor.chassis_id = chassis.id.hex(":") if isinstance(chassis.id, bytes) else str(chassis.id)
        except Exception:
            neighbor.chassis_id = str(chassis.id)

    if packet.haslayer(LLDPDUSystemName):
        neighbor.system_name = packet[LLDPDUSystemName].system_name.decode("utf-8", errors="replace")

    if packet.haslayer(LLDPDUPortDescription):
        neighbor.port_description = packet[LLDPDUPortDescription].description.decode("utf-8", errors="replace")

    if packet.haslayer(LLDPDUManagementAddress):
        mgmt = packet[LLDPDUManagementAddress]
        try:
            addr_bytes = mgmt.management_address
            if len(addr_bytes) == 4:
                neighbor.management_address = ".".join(str(b) for b in addr_bytes)
        except Exception:
            pass

    return neighbor


def capture_lldp_neighbors(interface: str, timeout: int = 30) -> List[LldpNeighbor]:
    """
    Berilgan interfeysda `timeout` soniya davomida LLDP xabarlarini
    "tinglaydi". MUHIM: agar shu vaqt ichida hech qanday LLDP xabari
    kelmasa (masalan test muhitida yoki switch LLDP yubormasa), bo'sh
    ro'yxat qaytaradi - bu xato emas, faqat "hozircha topilmadi".
    """
    neighbors = []

    def _handler(pkt):
        n = _parse_lldp_packet(pkt, interface)
        if n:
            neighbors.append(n)

    try:
        sniff(iface=interface, filter="ether dst 01:80:c2:00:00:0e", prn=_handler, timeout=timeout, store=False)
    except PermissionError:
        logger.error("LLDP capture uchun ruxsat yetarli emas - root/CAP_NET_RAW kerak")
        return []
    except Exception as exc:
        logger.error(f"LLDP capture xatoligi: {exc}")
        return []

    logger.info(f"LLDP capture ({interface}, {timeout}s): {len(neighbors)} ta xabar")
    return neighbors
