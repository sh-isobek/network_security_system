"""
UniFi Discovery - network_discovery paketi.

`response/unifi_adapter.py` bilan bir xil autentifikatsiya usuli,
lekin bu yerda bloklash o'rniga klientlar RO'YXATINI o'qish uchun.
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger("unifi_discovery")

UNIFI_CONTROLLER_URL = os.getenv("UNIFI_CONTROLLER_URL", "")
UNIFI_USERNAME = os.getenv("UNIFI_USERNAME", "")
UNIFI_PASSWORD = os.getenv("UNIFI_PASSWORD", "")
UNIFI_SITE = os.getenv("UNIFI_SITE", "default")


@dataclass
class UnifiClient:
    ip: Optional[str]
    mac: str
    hostname: Optional[str]
    is_wired: bool
    ap_mac: Optional[str] = None  # ulangan Access Point


def get_unifi_clients(timeout: int = 10) -> List[UnifiClient]:
    """
    UniFi Controller'dan hozir ulangan barcha klientlar ro'yxatini
    oladi. Controller mavjud bo'lmasa/ulanib bo'lmasa, bo'sh ro'yxat
    qaytaradi (xatoni "hech kim topilmadi" bilan aralashtirmaslik
    uchun bu funksiya chaqiruvchisi alohida log/monitoring qo'shishi
    tavsiya etiladi - bu yerda faqat bo'sh natija).
    """
    if not UNIFI_CONTROLLER_URL or not UNIFI_USERNAME:
        logger.warning("UNIFI_CONTROLLER_URL/UNIFI_USERNAME sozlanmagan")
        return []

    session = requests.Session()
    try:
        login_resp = session.post(
            f"{UNIFI_CONTROLLER_URL}/api/auth/login",
            json={"username": UNIFI_USERNAME, "password": UNIFI_PASSWORD},
            verify=False, timeout=timeout,
        )
        if login_resp.status_code != 200:
            logger.error(f"UniFi login muvaffaqiyatsiz: HTTP {login_resp.status_code}")
            return []

        clients_resp = session.get(
            f"{UNIFI_CONTROLLER_URL}/proxy/network/api/s/{UNIFI_SITE}/stat/sta",
            verify=False, timeout=timeout,
        )
        if clients_resp.status_code != 200:
            logger.error(f"UniFi klientlar ro'yxatini olib bo'lmadi: HTTP {clients_resp.status_code}")
            return []

        data = clients_resp.json().get("data", [])
        clients = [
            UnifiClient(
                ip=c.get("ip"),
                mac=c.get("mac", "").upper(),
                hostname=c.get("hostname") or c.get("name"),
                is_wired=c.get("is_wired", False),
                ap_mac=c.get("ap_mac"),
            )
            for c in data
        ]
        logger.info(f"UniFi: {len(clients)} ta klient topildi")
        return clients

    except requests.RequestException as exc:
        logger.error(f"UniFi Controller'ga ulanib bo'lmadi: {exc}")
        return []
