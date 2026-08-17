"""
UniFi Discovery - network_discovery paketi.

`response/unifi_adapter.py` bilan bir xil autentifikatsiya usuli,
lekin bu yerda bloklash o'rniga klientlar RO'YXATINI o'qish uchun.

MUHIM: UniFi Controller ikki xil "shakl"da bo'ladi, va ularning API
yo'llari BOSHQACHA:
  1. **UniFi OS konsoli** (UDM, UDM-Pro, UDR, Cloud Key Gen2+) -
     standart HTTPS port 443, API `/proxy/network/...` prefiksi bilan,
     login `/api/auth/login`.
  2. **Self-hosted / klassik dastur** (masalan Docker orqali -
     `jacobalberty/unifi`, `linuxserver/unifi-controller`) - odatda
     8443-port (yoki Docker orqali boshqa portga moslashtirilgan,
     masalan 11443), API to'g'ridan-to'g'ri `/api/...`, login
     `/api/login`.

Standart bo'lmagan port (masalan 11443) - bu odatda **self-hosted**
konfiguratsiyaga ishora qiladi (UniFi OS har doim 443-portda ishlaydi).
`UNIFI_OS_CONSOLE` muhit o'zgaruvchisi orqali qaysi turini
ishlatishni aniq belgilang.
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
# "true" = UniFi OS konsoli (UDM/UDR/Cloud Key G2+), "false" = self-hosted
# klassik dastur (masalan Docker). Standart bo'lmagan port (8443 emas,
# 443 emas) ishlatilganda odatda "false" to'g'ri bo'ladi.
UNIFI_OS_CONSOLE = os.getenv("UNIFI_OS_CONSOLE", "true").lower() in ("true", "1", "yes")


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

    if UNIFI_OS_CONSOLE:
        login_path = "/api/auth/login"
        clients_path = f"/proxy/network/api/s/{UNIFI_SITE}/stat/sta"
    else:
        login_path = "/api/login"
        clients_path = f"/api/s/{UNIFI_SITE}/stat/sta"

    session = requests.Session()
    try:
        login_resp = session.post(
            f"{UNIFI_CONTROLLER_URL}{login_path}",
            json={"username": UNIFI_USERNAME, "password": UNIFI_PASSWORD},
            verify=False, timeout=timeout,
        )
        if login_resp.status_code != 200:
            logger.error(f"UniFi login muvaffaqiyatsiz: HTTP {login_resp.status_code} ({login_path})")
            return []

        clients_resp = session.get(
            f"{UNIFI_CONTROLLER_URL}{clients_path}",
            verify=False, timeout=timeout,
        )
        if clients_resp.status_code != 200:
            logger.error(f"UniFi klientlar ro'yxatini olib bo'lmadi: HTTP {clients_resp.status_code} ({clients_path})")
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
