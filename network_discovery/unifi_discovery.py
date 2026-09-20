"""
UniFi Discovery - network_discovery paketi.

`response/unifi_adapter.py` bilan bir xil autentifikatsiya usuli,
lekin bu yerda bloklash o'rniga klientlar RO'YXATINI o'qish uchun.

FAQAT Integration API (v1) - API Key (token) orqali (Network
Application 9.1.105+). Login/parol orqali kirish OLIB TASHLANGAN:
UniFi hisobida 2-bosqichli autentifikatsiya (pochtaga tasdiqlash kodi)
yoqilgan, shuning uchun u usul ishlamaydi. Har bir so'rovga
`X-API-Key` sarlavhasi yuboriladi. Sayt ID **UUID** ko'rinishida
(masalan "88f7af54-98f8-306a-a1c7-c9349722b1f6"), sayt NOMI emas.
Manzil: `{CONTROLLER_URL}/proxy/network/integration/v1/...`
API kalitni yaratish: UniFi Network > Control Plane > Integrations.
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger("unifi_discovery")


@dataclass
class UnifiClient:
    ip: Optional[str]
    mac: str
    hostname: Optional[str]
    is_wired: bool
    uplink_device_id: Optional[str] = None  # ulangan AP/switch'ning UUID'si
                                               # (MAC EMAS - real API javobida
                                               # "uplinkDeviceId" nomi bilan
                                               # UUID sifatida keladi, bu real
                                               # test orqali aniqlangan)


def _get_clients_via_api_key(controller_url: str, api_key: str, site_id: str,
                              verify_ssl: bool, timeout: int) -> Optional[List[UnifiClient]]:
    """
    Yangi Integration API (v1) orqali - login bosqichisiz, to'g'ridan-
    to'g'ri API Key bilan. Muvaffaqiyatsiz bo'lsa `None` qaytaradi
    (chaqiruvchisi zaxira usulga o'tishi mumkin bo'lishi uchun -
    bo'sh ro'yxat `[]` esa "muvaffaqiyatli, lekin klient yo'q" degani).

    MUHIM (real testda topilgan jiddiy xato, tuzatilgan): bu API
    natijalarni SAHIFALAB (paginate) qaytaradi - standart sahifa
    hajmi 25 ta, hatto jami 195 ta klient bo'lsa ham. Shuning uchun
    BARCHA sahifalar `offset` ortirilib, to'liq yig'ib olinishi SHART
    - aks holda faqat birinchi ~25 ta klient qaytarilib, qolganlari
    "yo'qolib" ketadi (bu aynan shu xato avval mavjud edi).
    """
    url = f"{controller_url}/proxy/network/integration/v1/sites/{site_id}/clients"
    headers = {"X-API-Key": api_key, "Accept": "application/json"}

    all_raw_clients = []
    offset = 0
    page_limit = 200  # so'rov limitini kattaroq qilib, sahifalar sonini kamaytiramiz
    max_pages = 50     # cheksiz tsikldan himoya (masalan API xato javob qaytarsa)

    for _ in range(max_pages):
        try:
            resp = requests.get(
                url, headers=headers, verify=verify_ssl, timeout=timeout,
                params={"offset": offset, "limit": page_limit},
            )
        except requests.RequestException as exc:
            logger.error(f"UniFi Integration API'ga ulanib bo'lmadi: {exc}")
            return None

        if resp.status_code != 200:
            logger.error(f"UniFi Integration API xatoligi: HTTP {resp.status_code} ({url}) - {resp.text[:200]}")
            return None

        try:
            payload = resp.json()
        except ValueError:
            logger.error("UniFi Integration API javobi JSON emas")
            return None

        if not isinstance(payload, dict):
            logger.error(f"UniFi Integration API kutilmagan javob formati: {type(payload)}")
            return None

        page_clients = payload.get("data", [])
        if not isinstance(page_clients, list):
            logger.error(f"UniFi Integration API 'data' maydoni ro'yxat emas: {type(page_clients)}")
            return None

        all_raw_clients.extend(page_clients)

        total_count = payload.get("totalCount", len(all_raw_clients))
        if len(all_raw_clients) >= total_count or not page_clients:
            break

        offset += len(page_clients)
    else:
        logger.warning(f"UniFi Integration API: {max_pages} sahifadan keyin ham to'xtamadi - qisman natija ishlatilmoqda")

    clients = []
    for c in all_raw_clients:
        mac = c.get("macAddress") or c.get("mac", "")
        clients.append(UnifiClient(
            ip=c.get("ipAddress") or c.get("ip"),
            mac=mac.upper(),
            hostname=c.get("name") or c.get("hostname"),
            is_wired=(c.get("type", "").upper() == "WIRED") if "type" in c else bool(c.get("is_wired", False)),
            uplink_device_id=c.get("uplinkDeviceId"),
        ))

    logger.info(f"UniFi (API Key): {len(clients)} ta klient topildi (barcha sahifalar)")
    return clients


def get_unifi_clients(timeout: int = 10) -> List[UnifiClient]:
    """
    UniFi Controller'dan hozir ulangan barcha klientlar ro'yxatini
    Integration API (API Key) orqali oladi. Sozlanmagan bo'lsa yoki
    ulanib bo'lmasa, bo'sh ro'yxat qaytaradi (exception ko'tarmaydi).

    MUHIM: barcha muhit o'zgaruvchilari HAR CHAQIRUVDA dinamik o'qiladi
    (modul darajasidagi "muzlab qolgan" konstanta emas).
    """
    controller_url = os.getenv("UNIFI_CONTROLLER_URL", "").rstrip("/")
    verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() in ("true", "1", "yes")
    api_key = os.getenv("UNIFI_API_KEY", "")
    site_id = os.getenv("UNIFI_SITE_ID", "")

    if not (controller_url and api_key and site_id):
        logger.warning("UNIFI_CONTROLLER_URL/UNIFI_API_KEY/UNIFI_SITE_ID sozlanmagan - UniFi discovery o'tkazib yuborildi")
        return []

    result = _get_clients_via_api_key(controller_url, api_key, site_id, verify_ssl, timeout)
    return result if result is not None else []
