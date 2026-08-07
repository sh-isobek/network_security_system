"""
CDP Mapper - network_discovery paketi.

CDP (Cisco Discovery Protocol) - LLDP'ning Cisco'ga xos muqobili,
faqat Cisco qurilmalari orasida ishlaydi. Ko'p sanoat switch'lari
(shu jumladan Cisco bo'lmaganlari ham moslik uchun) buni qo'llab-
quvvatlaydi.
"""
import logging
from dataclasses import dataclass
from typing import List, Optional

from scapy.all import sniff
from scapy.contrib.cdp import CDPMsgDeviceID, CDPMsgPortID, CDPMsgSoftwareVersion, CDPMsgPlatform, CDPv2_HDR

logger = logging.getLogger("cdp_mapper")

CDP_MULTICAST_MAC = "01:00:0c:cc:cc:cc"


@dataclass
class CdpNeighbor:
    device_id: Optional[str] = None
    port_id: Optional[str] = None
    platform: Optional[str] = None
    software_version: Optional[str] = None
    received_on_interface: str = ""


def _parse_cdp_packet(packet, interface: str) -> Optional[CdpNeighbor]:
    if not packet.haslayer(CDPv2_HDR):
        return None

    neighbor = CdpNeighbor(received_on_interface=interface)

    if packet.haslayer(CDPMsgDeviceID):
        neighbor.device_id = packet[CDPMsgDeviceID].val.decode("utf-8", errors="replace")
    if packet.haslayer(CDPMsgPortID):
        neighbor.port_id = packet[CDPMsgPortID].iface.decode("utf-8", errors="replace")
    if packet.haslayer(CDPMsgPlatform):
        neighbor.platform = packet[CDPMsgPlatform].val.decode("utf-8", errors="replace")
    if packet.haslayer(CDPMsgSoftwareVersion):
        neighbor.software_version = packet[CDPMsgSoftwareVersion].val.decode("utf-8", errors="replace")

    return neighbor


def capture_cdp_neighbors(interface: str, timeout: int = 30) -> List[CdpNeighbor]:
    """LLDP'dagi bilan bir xil mantiq - CDP multicast manziliga (01:00:0c:cc:cc:cc) filtrlangan."""
    neighbors = []

    def _handler(pkt):
        n = _parse_cdp_packet(pkt, interface)
        if n:
            neighbors.append(n)

    try:
        sniff(iface=interface, filter="ether dst 01:00:0c:cc:cc:cc", prn=_handler, timeout=timeout, store=False)
    except PermissionError:
        logger.error("CDP capture uchun ruxsat yetarli emas - root/CAP_NET_RAW kerak")
        return []
    except Exception as exc:
        logger.error(f"CDP capture xatoligi: {exc}")
        return []

    logger.info(f"CDP capture ({interface}, {timeout}s): {len(neighbors)} ta xabar")
    return neighbors
