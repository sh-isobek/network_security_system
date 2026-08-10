"""
Wireless Controller Discovery (Aruba, Ruijie, Cisco WLC) - network_discovery paketi.

MUHIM ARXITEKTURA QARORI: har bir vendor'ning o'z proprietar API'si bor
(Aruba Central REST API, Ruijie Cloud/eWeb API, Cisco WLC uchun
odatda SNMP yoki NETCONF). Umumiy, vendor-neytral asos sifatida
**SNMP** ishlatiladi (`network_discovery/snmp_discovery.py`dagi bilan
bir xil, sinovdan o'tgan yondashuv) - deyarli barcha WLC'lar standart
MIB-II'ni qo'llab-quvvatlaydi va WLAN-specific MIB'lar orqali ulangan
klientlar ro'yxatini berish mumkin.

Vendor-specific REST API'lar (Aruba Central, Ruijie Cloud) uchun
alohida autentifikatsiya/token boshqaruvi kerak - bu yerda Aruba
Central uchun namuna keltirilgan, xuddi shu andozani Ruijie/Cisco
uchun ham qo'llash mumkin.

HALOL CHEKLOV: real Aruba Central/Ruijie Cloud hisobi mavjud emas -
graceful fail xatti-harakati test qilingan (boshqa controller
modullari - UniFi, VMware - bilan bir xil).
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

from network_discovery.snmp_discovery import snmp_discover, SnmpDeviceInfo

logger = logging.getLogger("wlc_discovery")

ARUBA_CENTRAL_URL = os.getenv("ARUBA_CENTRAL_URL", "")
ARUBA_CENTRAL_TOKEN = os.getenv("ARUBA_CENTRAL_TOKEN", "")

RUIJIE_CLOUD_URL = os.getenv("RUIJIE_CLOUD_URL", "")
RUIJIE_API_KEY = os.getenv("RUIJIE_API_KEY", "")
RUIJIE_API_SECRET = os.getenv("RUIJIE_API_SECRET", "")


@dataclass
class WirelessClient:
    mac: str
    ip: Optional[str] = None
    ssid: Optional[str] = None
    ap_name: Optional[str] = None
    signal_strength: Optional[int] = None


def discover_wlc_via_snmp(ip: str, community: str = "public") -> Optional[SnmpDeviceInfo]:
    """
    Vendor-neytral - istalgan SNMP-qo'llab-quvvatlaydigan WLC (Aruba,
    Ruijie, Cisco, va boshqalar) uchun ishlaydi. Bu allaqachon sinovdan
    o'tgan `snmp_discovery.py`ning to'g'ridan-to'g'ri qo'llanilishi.
    """
    return snmp_discover(ip, community=community)


def discover_aruba_central_clients(timeout: int = 15) -> List[WirelessClient]:
    """Aruba Central REST API orqali ulangan Wi-Fi klientlarini oladi."""
    if not ARUBA_CENTRAL_URL or not ARUBA_CENTRAL_TOKEN:
        logger.warning("ARUBA_CENTRAL_URL/ARUBA_CENTRAL_TOKEN sozlanmagan")
        return []

    try:
        resp = requests.get(
            f"{ARUBA_CENTRAL_URL}/monitoring/v1/clients/wireless",
            headers={"Authorization": f"Bearer {ARUBA_CENTRAL_TOKEN}"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.error(f"Aruba Central xatoligi: HTTP {resp.status_code}")
            return []

        clients_raw = resp.json().get("clients", [])
        clients = [
            WirelessClient(
                mac=c.get("macaddr", "").upper(), ip=c.get("ip_address"),
                ssid=c.get("network"), ap_name=c.get("associated_device_name"),
                signal_strength=c.get("rssi"),
            )
            for c in clients_raw
        ]
        logger.info(f"Aruba Central: {len(clients)} ta klient topildi")
        return clients

    except requests.RequestException as exc:
        logger.error(f"Aruba Central'ga ulanib bo'lmadi: {exc}")
        return []


def discover_ruijie_cloud_clients(timeout: int = 15) -> List[WirelessClient]:
    """Ruijie Cloud API orqali ulangan klientlarni oladi."""
    if not RUIJIE_CLOUD_URL or not RUIJIE_API_KEY:
        logger.warning("RUIJIE_CLOUD_URL/RUIJIE_API_KEY sozlanmagan")
        return []

    try:
        resp = requests.get(
            f"{RUIJIE_CLOUD_URL}/api/v1/clients",
            headers={"X-API-Key": RUIJIE_API_KEY, "X-API-Secret": RUIJIE_API_SECRET},
            timeout=timeout,
        )
        if resp.status_code != 200:
            logger.error(f"Ruijie Cloud xatoligi: HTTP {resp.status_code}")
            return []

        clients_raw = resp.json().get("data", [])
        clients = [
            WirelessClient(mac=c.get("mac", "").upper(), ip=c.get("ip"), ssid=c.get("ssid"), ap_name=c.get("apName"))
            for c in clients_raw
        ]
        logger.info(f"Ruijie Cloud: {len(clients)} ta klient topildi")
        return clients

    except requests.RequestException as exc:
        logger.error(f"Ruijie Cloud'ga ulanib bo'lmadi: {exc}")
        return []
