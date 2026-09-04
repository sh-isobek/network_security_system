"""
Ruijie Cloud Discovery - network_discovery paketi.

`unifi_discovery.py` bilan bir xil naqsh (bir xil interfeys - IP/MAC/
hostname/is_wired ro'yxati), lekin Ruijie Cloud (Reyee/RG seriyali
switch/AP'lar) uchun.

Autentifikatsiya (Ruijie Cloud Open API, rasmiy `pyruijie` mijoz
kutubxonasi manba kodi orqali tasdiqlangan - loyihada hozircha
Ruijie'ning o'z rasmiy PDF hujjatiga to'g'ridan-to'g'ri kirish imkoni
bo'lmagani uchun bu ochiq-manbali mijoz kod DARAJASIDA tekshirilgan):

  1. Avval bitta martalik `access_token` olinadi:
     `POST {base_url}/service/api/oauth20/client/access_token
     ?token=<RUIJIE_API_TOKEN>` tanasida `{"appid": ..., "secret": ...}`
     - `RUIJIE_API_TOKEN` - Ruijie'ga alohida so'rov (email/kompaniya/
       maqsad) orqali BIR MARTA so'rab olinadigan doimiy token (UniFi'ning
       API Key'idan farqli, bu "ilova" darajasidagi ruxsat, alohida
       o'zgaruvchan `accessToken`ni olish uchun ishlatiladi).
     - `RUIJIE_APP_ID`/`RUIJIE_APP_SECRET` - Ruijie Cloud shaxsiy
       kabinetida ("Open Platform"/"Developer") yaratiladigan ilova
       kalitlari.
  2. Olingan `accessToken` keyingi HAR BIR so'rovga `access_token`
     query parametri sifatida qo'shiladi (UniFi'ning `X-API-Key`
     sarlavhasidan farqli - bu yerda query parametr).
  3. Javob konverti har doim `{"code": 0, ...}` (muvaffaqiyat) yoki
     `{"code": <0 emas>, "msg": "..."}` (xato) ko'rinishida.

MUHIM (halol cheklov): bu modul rasmiy Ruijie API hujjatiga emas,
ochiq-manbali `pyruijie` mijoz kutubxonasining (Apache 2.0, GitHub)
manba kodiga qarab yozilgan - u yerda so'rov yo'llari/maydon nomlari
aniq ko'rsatilgan, lekin ba'zi maydonlarning TO'LIQ qiymat diapazoni
(masalan `connectType` uchun "WIRED"/"WIRELESS" dan boshqa qanday
qiymatlar bo'lishi mumkinligi) noma'lum - shuning uchun `_is_wired()`
funksiyasi ataylab KENGROQ (substring) tekshiruv qiladi, UniFi'nikiga
o'xshab.
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger("ruijie_discovery")

_AUTH_PATH = "/service/api/oauth20/client/access_token"
_GROUP_TREE_PATH = "/service/api/group/single/tree"
_CLIENTS_PATH = "/service/api/open/v1/dev/user/current-user"

_DEFAULT_BASE_URL = "https://cloud-us.ruijienetworks.com"


@dataclass
class RuijieClient:
    ip: Optional[str]
    mac: str
    hostname: Optional[str]
    is_wired: bool
    linked_device: Optional[str] = None  # ulangan switch/AP nomi (MAC/UUID emas - "linkedDevice")
    ssid: Optional[str] = None


def _is_wired(connect_type: Optional[str]) -> bool:
    """`connectType` maydonining TO'LIQ qiymat diapazoni hujjatlashtirilmagan
    (yuqoridagi modul izohiga qarang) - shuning uchun keng, katta-kichik
    harfga sezgir bo'lmagan qidiruv qilinadi ("WIRED"/"wired"/"CABLE" va h.k.).

    MUHIM (real testda topilgan xato, tuzatilgan): oddiy `"wire" in value`
    tekshiruvi "WIRELESS" so'zining ICHIDA ham "wire" substring'i borligi
    sababli uni HAM noto'g'ri "wired" deb belgilar edi - shuning uchun
    "wireless"/"wifi"/"wlan" avval ANIQ istisno qilinadi."""
    if not connect_type:
        return False
    v = connect_type.strip().lower()
    if "wireless" in v or "wifi" in v or "wlan" in v:
        return False
    return "wire" in v or "cable" in v or "lan" in v


def _get_access_token(base_url: str, app_id: str, app_secret: str, api_token: str,
                       verify_ssl: bool, timeout: int) -> Optional[str]:
    """Ruijie Cloud'dan so'rovlar uchun vaqtinchalik `accessToken` oladi.
    Muvaffaqiyatsiz bo'lsa `None` qaytaradi (exception ko'tarmaydi -
    chaqiruvchisi bo'sh ro'yxatga qaytishi uchun)."""
    try:
        resp = requests.post(
            f"{base_url}{_AUTH_PATH}",
            params={"token": api_token},
            json={"appid": app_id, "secret": app_secret},
            verify=verify_ssl, timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.error(f"Ruijie Cloud'ga ulanib bo'lmadi (auth): {exc}")
        return None

    if resp.status_code != 200:
        logger.error(f"Ruijie Cloud autentifikatsiya xatoligi: HTTP {resp.status_code} - {resp.text[:200]}")
        return None

    try:
        payload = resp.json()
    except ValueError:
        logger.error("Ruijie Cloud auth javobi JSON emas")
        return None

    if payload.get("code") != 0:
        logger.error(f"Ruijie Cloud autentifikatsiya rad etildi: {payload.get('msg', 'nomalum xato')} (code={payload.get('code')})")
        return None

    token = payload.get("accessToken")
    if not token:
        logger.error("Ruijie Cloud auth javobida 'accessToken' topilmadi")
        return None

    return token


def _collect_building_group_ids(group: dict, out: list) -> None:
    """Guruh daraxtini (`subGroups` ichma-ich massivi) rekursiv aylanib,
    "BUILDING" turidagi guruhlarning `groupId`larini yig'adi - bular
    UniFi'dagi "site"ga o'xshash, klientlar shu daraja bo'yicha so'raladi."""
    if not isinstance(group, dict):
        return
    if group.get("type") == "BUILDING" and group.get("groupId") is not None:
        out.append(str(group["groupId"]))
    for sub in group.get("subGroups", []) or []:
        _collect_building_group_ids(sub, out)


def _get_group_ids(base_url: str, access_token: str, verify_ssl: bool, timeout: int) -> List[str]:
    """`RUIJIE_GROUP_ID` sozlanmagan holatda, hisobdagi BARCHA
    ("BUILDING" turidagi) guruhlarni avtomatik topadi - shunda foydalanuvchi
    har bir loyiha/filial uchun alohida ID qidirishi shart emas."""
    try:
        resp = requests.get(
            f"{base_url}{_GROUP_TREE_PATH}",
            params={"depth": "DEVICE", "access_token": access_token},
            verify=verify_ssl, timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.error(f"Ruijie Cloud guruh daraxtini olib bo'lmadi: {exc}")
        return []

    if resp.status_code != 200:
        logger.error(f"Ruijie Cloud guruh daraxti xatoligi: HTTP {resp.status_code}")
        return []

    try:
        payload = resp.json()
    except ValueError:
        logger.error("Ruijie Cloud guruh daraxti javobi JSON emas")
        return []

    if payload.get("code") != 0:
        logger.error(f"Ruijie Cloud guruh daraxti rad etildi: {payload.get('msg', 'nomalum xato')}")
        return []

    root = payload.get("groups")
    if not isinstance(root, dict):
        logger.error("Ruijie Cloud guruh daraxti kutilmagan formatda ('groups' obyekt emas)")
        return []

    group_ids: List[str] = []
    _collect_building_group_ids(root, group_ids)
    return group_ids


def _get_clients_for_group(base_url: str, access_token: str, group_id: str,
                            verify_ssl: bool, timeout: int) -> Optional[List[RuijieClient]]:
    """Bitta guruh (loyiha/filial) uchun hozir ulangan klientlar
    ro'yxatini, TO'LIQ sahifalab (pagination) oladi. Muvaffaqiyatsiz
    bo'lsa `None` (UniFi'nikiga o'xshab - "bo'sh" bilan "xato"ni
    farqlash uchun)."""
    all_raw: List[dict] = []
    page_index = 1
    page_size = 200
    max_pages = 50  # cheksiz tsikldan himoya

    for _ in range(max_pages):
        try:
            resp = requests.get(
                f"{base_url}{_CLIENTS_PATH}",
                params={
                    "group_id": group_id,
                    "page_index": page_index,
                    "page_size": page_size,
                    "access_token": access_token,
                },
                verify=verify_ssl, timeout=timeout,
            )
        except requests.RequestException as exc:
            logger.error(f"Ruijie Cloud klientlar so'rovi muvaffaqiyatsiz (guruh {group_id}): {exc}")
            return None

        if resp.status_code != 200:
            logger.error(f"Ruijie Cloud klientlar xatoligi: HTTP {resp.status_code} (guruh {group_id})")
            return None

        try:
            payload = resp.json()
        except ValueError:
            logger.error("Ruijie Cloud klientlar javobi JSON emas")
            return None

        if payload.get("code") != 0:
            logger.error(f"Ruijie Cloud klientlar so'rovi rad etildi: {payload.get('msg', 'nomalum xato')}")
            return None

        page_clients = payload.get("list", [])
        if not isinstance(page_clients, list):
            logger.error("Ruijie Cloud klientlar javobida 'list' massiv emas")
            return None

        if not page_clients:
            break
        all_raw.extend(page_clients)

        total_count = payload.get("totalCount", len(all_raw))
        if len(all_raw) >= total_count:
            break
        page_index += 1
    else:
        logger.warning(f"Ruijie Cloud: {max_pages} sahifadan keyin ham to'xtamadi (guruh {group_id}) - qisman natija ishlatilmoqda")

    clients = []
    for c in all_raw:
        mac = (c.get("mac") or "").upper()
        if not mac:
            continue
        clients.append(RuijieClient(
            ip=c.get("ip"),
            mac=mac,
            hostname=c.get("userName") or c.get("deviceName") or c.get("staModel"),
            is_wired=_is_wired(c.get("connectType")),
            linked_device=c.get("linkedDevice"),
            ssid=c.get("ssid"),
        ))
    return clients


def get_ruijie_clients(timeout: int = 10) -> List[RuijieClient]:
    """
    Ruijie Cloud'ga ulangan barcha loyiha(lar)dan hozir ulangan
    klientlar ro'yxatini oladi. Sozlanmagan yoki xato holatda bo'sh
    ro'yxat qaytaradi (exception ko'tarmaydi) - `unifi_discovery.
    get_unifi_clients()` bilan bir xil kafolat.

    MUHIM: barcha muhit o'zgaruvchilari HAR CHAQIRUVDA dinamik
    o'qiladi (modul darajasidagi "muzlab qolgan" konstanta emas) - bu
    loyihada bir necha marta uchragan xato turkumini oldini oladi.
    """
    base_url = os.getenv("RUIJIE_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")
    app_id = os.getenv("RUIJIE_APP_ID", "")
    app_secret = os.getenv("RUIJIE_APP_SECRET", "")
    api_token = os.getenv("RUIJIE_API_TOKEN", "")
    verify_ssl = os.getenv("RUIJIE_VERIFY_SSL", "true").lower() in ("true", "1", "yes")
    configured_group_id = os.getenv("RUIJIE_GROUP_ID", "").strip()

    if not (app_id and app_secret and api_token):
        logger.debug("RUIJIE_APP_ID/RUIJIE_APP_SECRET/RUIJIE_API_TOKEN sozlanmagan - Ruijie Cloud discovery o'tkazib yuborildi")
        return []

    access_token = _get_access_token(base_url, app_id, app_secret, api_token, verify_ssl, timeout)
    if not access_token:
        return []

    if configured_group_id:
        group_ids = [configured_group_id]
    else:
        group_ids = _get_group_ids(base_url, access_token, verify_ssl, timeout)
        if not group_ids:
            logger.warning("Ruijie Cloud: hech qanday guruh (loyiha) topilmadi")
            return []

    seen_macs = set()
    all_clients: List[RuijieClient] = []
    for group_id in group_ids:
        group_clients = _get_clients_for_group(base_url, access_token, group_id, verify_ssl, timeout)
        if group_clients is None:
            continue
        for c in group_clients:
            if c.mac in seen_macs:
                continue
            seen_macs.add(c.mac)
            all_clients.append(c)

    logger.info(f"Ruijie Cloud: {len(all_clients)} ta klient topildi ({len(group_ids)} ta guruh bo'yicha)")
    return all_clients
