"""
UniFi Discovery - network_discovery paketi.

`response/unifi_adapter.py` bilan bir xil autentifikatsiya usuli,
lekin bu yerda bloklash o'rniga klientlar RO'YXATINI o'qish uchun.

MUHIM: ikkita mutlaqo boshqacha UniFi API avlodi mavjud:

  1. **Integration API (v1) - API Key orqali** (2025-yildan, Network
     Application 9.1.105+) - ASOSIY va TAVSIYA ETILGAN usul. Login
     bosqichi UMUMAN YO'Q - har bir so'rovga `X-API-Key` sarlavhasi
     bilan API kalit yuboriladi. Sayt ID **UUID** ko'rinishida
     (masalan "88f7af54-98f8-306a-a1c7-c9349722b1f6"), sayt NOMI emas.
     Manzil: `{CONTROLLER_URL}/proxy/network/integration/v1/...`
     API kalitni yaratish: UniFi Network > Control Plane > Integrations.

  2. **Eski, legacy API - login/parol orqali** (zaxira usul, faqat
     API Key mavjud bo'lmagan eski dasturlar uchun). Bu holatda ham
     ikkita ko'rinish bor - UniFi OS konsoli (`/api/auth/login`) va
     self-hosted klassik dastur (`/api/login`).

Qaysi usul ishlatilishini aniqlash: agar `UNIFI_API_KEY` sozlangan
bo'lsa, u ustuvor (login umuman qilinmaydi). Aks holda login/parolga
qaytiladi.
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


def _get_clients_via_login(controller_url: str, username: str, password: str,
                            site: str, os_console: bool, verify_ssl: bool, timeout: int) -> List[UnifiClient]:
    """Eski, legacy usul - login/parol orqali (API Key mavjud bo'lmaganda zaxira)."""
    if not controller_url or not username:
        logger.warning("UNIFI_API_KEY ham, UNIFI_USERNAME ham sozlanmagan")
        return []

    if os_console:
        login_path = "/api/auth/login"
        clients_path = f"/proxy/network/api/s/{site}/stat/sta"
    else:
        login_path = "/api/login"
        clients_path = f"/api/s/{site}/stat/sta"

    session = requests.Session()
    try:
        login_resp = session.post(
            f"{controller_url}{login_path}",
            json={"username": username, "password": password},
            verify=verify_ssl, timeout=timeout,
        )
        if login_resp.status_code != 200:
            logger.error(f"UniFi login muvaffaqiyatsiz: HTTP {login_resp.status_code} ({login_path})")
            return []

        clients_resp = session.get(
            f"{controller_url}{clients_path}",
            verify=verify_ssl, timeout=timeout,
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
                uplink_device_id=c.get("ap_mac"),  # legacy API'da bu haqiqatan AP MAC manzili
            )
            for c in data
        ]
        logger.info(f"UniFi (login/parol): {len(clients)} ta klient topildi")
        return clients

    except requests.RequestException as exc:
        logger.error(f"UniFi Controller'ga ulanib bo'lmadi: {exc}")
        return []


def get_unifi_clients(timeout: int = 10) -> List[UnifiClient]:
    """
    UniFi Controller'dan hozir ulangan barcha klientlar ro'yxatini
    oladi. `UNIFI_API_KEY` sozlangan bo'lsa (tavsiya etiladi) - yangi
    Integration API ishlatiladi. Aks holda eski login/parol usuliga
    qaytiladi. Controller mavjud bo'lmasa/ulanib bo'lmasa, bo'sh
    ro'yxat qaytaradi (exception ko'tarmaydi).

    MUHIM: barcha muhit o'zgaruvchilari HAR CHAQIRUVDA dinamik o'qiladi
    (modul darajasidagi "muzlab qolgan" konstanta emas) - bu loyihada
    bir necha marta uchragan xato turkumini oldini oladi.
    """
    controller_url = os.getenv("UNIFI_CONTROLLER_URL", "").rstrip("/")
    verify_ssl = os.getenv("UNIFI_VERIFY_SSL", "false").lower() in ("true", "1", "yes")

    api_key = os.getenv("UNIFI_API_KEY", "")
    site_id = os.getenv("UNIFI_SITE_ID", "")

    if controller_url and api_key and site_id:
        result = _get_clients_via_api_key(controller_url, api_key, site_id, verify_ssl, timeout)
        if result is not None:
            return result
        logger.warning("API Key usuli muvaffaqiyatsiz bo'ldi - login/parol zaxira usuliga o'tilmoqda (agar sozlangan bo'lsa)")

    username = os.getenv("UNIFI_USERNAME", "")
    password = os.getenv("UNIFI_PASSWORD", "")
    site = os.getenv("UNIFI_SITE", "default")
    os_console = os.getenv("UNIFI_OS_CONSOLE", "true").lower() in ("true", "1", "yes")

    return _get_clients_via_login(controller_url, username, password, site, os_console, verify_ssl, timeout)
