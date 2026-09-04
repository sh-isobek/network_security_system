"""
Ruijie Cloud Discovery - network_discovery paketi.

`network_discovery/unifi_discovery.py` bilan bir xil vazifa (ulangan
klientlar ro'yxatini olib, `asset_inventory.py` orqali DB'ga yozish
uchun), lekin Ruijie Cloud (Reyee/RG-CBS, `cloud.ruijienetworks.com`)
Open API'siga qarshi.

Autentifikatsiya oqimi (rasmiy "Ruijie Cloud API Reference V2.0.3"
hujjati + real HTTP orqali tasdiqlangan):

  1. `POST {base_url}/service/api/oauth20/client/access_token?token=<STATIC_TOKEN>`
     JSON body: `{"appid": ..., "secret": ...}` -> `access_token` (2 soat amal qiladi).

     MUHIM (halol izoh): `token` so'rov parametri sizning `appid`/
     `secret`ingizga BOG'LIQ EMAS - bu hujjatda ko'rsatilgan, barcha
     mijozlar uchun BIR XIL qat'iy (o'zgarmas) qiymat (`RUIJIE_STATIC_
     TOKEN`, standart qiymati quyida) - ehtimol API'ning qaysi kanal
     (uchinchi tomon integratsiyasi) orqali chaqirilayotganini
     belgilaydi, mijoz-maxsus maxfiy kalit emas. Bu **real so'rov
     bilan tasdiqlangan** - to'g'ri `appid`/`secret` + shu qat'iy
     qiymat bilan `code:0` (muvaffaqiyat) qaytdi.
  2. Keyingi barcha so'rovlarga `access_token` SO'ROV PARAMETRI
     (header EMAS) sifatida qo'shiladi: `?access_token=...`.
  3. `GET /service/api/group/single/tree?access_token=...` - barcha
     loyihalar/filiallar (guruhlar) daraxti (ichma-ich - `subGroups`).
  4. `GET /service/api/maint/devices?group_id=<id>&page=1&per_page=100&access_token=...`
     - shu guruhdagi boshqariladigan qurilmalar (switch/AP/gateway).
  5. `GET /service/api/open/v1/dev/user/current-user?group_id=<id>&page_index=1&page_size=200&access_token=...`
     - shu guruhda hozir ulangan klientlar (MAC/IP/ishlab chiqaruvchi/
     ulanish turi).

MUHIM (halol cheklov, UniFi bilan bir xil naqsh): bu modul FAQAT
o'qish (discovery) uchun. Klientni bloklash/tarmoqdan uzish uchun
Ruijie Cloud'ning ochiq, rasmiy hujjatlashtirilgan API endpoint'i
TOPILMADI (na rasmiy kutubxonalarda, na hujjatlarda) - shuning uchun
`response/ruijie_adapter.py` hali qurilmagan. Buni qurish uchun
foydalanuvchidan Ruijie Cloud veb-interfeysida "bloklash" amalini
DevTools orqali ushlab, aniq endpoint/payload formatini olish so'ralgan
(taxminiy/tasdiqlanmagan endpoint bilan yozish - real qurilmani
kutilmaganda tarmoqdan uzib qo'yish xavfi bor, xavfsiz emas).
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger("ruijie_discovery")

AUTH_PATH = "/service/api/oauth20/client/access_token"
GROUPS_PATH = "/service/api/group/single/tree"
DEVICES_PATH = "/service/api/maint/devices"
CLIENTS_PATH = "/service/api/open/v1/dev/user/current-user"

# Rasmiy hujjatda ko'rsatilgan, barcha mijozlar uchun BIR XIL qat'iy
# qiymat (mijoz-maxsus MAXFIY kalit EMAS) - real so'rov bilan
# tasdiqlangan. `RUIJIE_STATIC_TOKEN` orqali qayta belgilash mumkin
# (agar Ruijie kelajakda buni o'zgartirsa).
DEFAULT_STATIC_TOKEN = "d63dss0a81e4415a889ac5b78fsc904a"


@dataclass
class RuijieClient:
    mac: str
    ip: Optional[str]
    hostname: Optional[str]
    is_wired: bool
    manufacturer: Optional[str] = None
    group_name: Optional[str] = None       # qaysi filial/guruh (masalan "Asosiy ofis")
    linked_device: Optional[str] = None    # ulangan switch/AP serial raqami


def _authenticate(base_url: str, app_id: str, app_secret: str,
                   static_token: str, timeout: int) -> Optional[str]:
    """`access_token` oladi. Muvaffaqiyatsiz bo'lsa (tarmoq xatosi,
    noto'g'ri kalit, ilova hali tasdiqlanmagan) `None` qaytaradi -
    xato ko'tarmaydi (chaqiruvchi jim ravishda bo'sh ro'yxatga
    qaytishi uchun, xuddi UniFi discovery'dagi kabi)."""
    url = f"{base_url}{AUTH_PATH}"
    try:
        resp = requests.post(
            url,
            params={"token": static_token},
            json={"appid": app_id, "secret": app_secret},
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        logger.error(f"Ruijie Cloud'ga ulanib bo'lmadi: {exc}")
        return None

    if resp.status_code != 200:
        logger.error(f"Ruijie Cloud autentifikatsiya xatoligi: HTTP {resp.status_code}")
        return None

    data = resp.json()
    if data.get("code") != 0:
        logger.error(f"Ruijie Cloud autentifikatsiya rad etildi: {data.get('msg')}")
        return None

    return data.get("accessToken")


def _get_all_group_ids(base_url: str, access_token: str, timeout: int) -> List[dict]:
    """Guruhlar (filiallar) daraxtini oladi va REKURSIV ravishda
    barcha guruhlarni (id + nom) tekshiladi - `groupId=0` (sun'iy
    "dumy" ildiz) bundan mustasno."""
    url = f"{base_url}{GROUPS_PATH}"
    try:
        resp = requests.get(url, params={"access_token": access_token}, timeout=timeout)
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.error(f"Ruijie guruhlar daraxtini olib bo'lmadi: {exc}")
        return []

    if data.get("code") != 0:
        logger.error(f"Ruijie guruhlar daraxti xatoligi: {data.get('msg')}")
        return []

    groups: List[dict] = []

    def _walk(node: dict):
        group_id = node.get("groupId")
        if group_id:  # 0 (sun'iy "dumy" ildiz) o'tkazib yuboriladi
            groups.append({"id": group_id, "name": node.get("name")})
        for child in node.get("subGroups") or []:
            _walk(child)

    root = data.get("groups") or {}
    _walk(root)
    return groups


def _get_clients_for_group(base_url: str, access_token: str, group_id, group_name: str,
                            timeout: int, page_size: int = 200, max_pages: int = 50) -> List[RuijieClient]:
    url = f"{base_url}{CLIENTS_PATH}"
    clients: List[RuijieClient] = []

    for page in range(1, max_pages + 1):
        try:
            resp = requests.get(
                url,
                params={
                    "access_token": access_token, "group_id": group_id,
                    "page_index": page, "page_size": page_size,
                },
                timeout=timeout,
            )
            data = resp.json()
        except (requests.RequestException, ValueError) as exc:
            logger.error(f"Ruijie klientlarini olib bo'lmadi (guruh {group_id}): {exc}")
            return clients

        if data.get("code") != 0:
            logger.warning(f"Ruijie klientlar so'rovi xatoligi (guruh {group_id}): {data.get('msg')}")
            return clients

        raw_clients = data.get("list") or []
        if not raw_clients:
            return clients

        for c in raw_clients:
            clients.append(RuijieClient(
                mac=c.get("mac", ""),
                ip=c.get("ip") or None,
                hostname=c.get("userName") or c.get("deviceName") or None,
                is_wired=(c.get("connectType") == "wire"),
                manufacturer=c.get("manufacturer"),
                group_name=c.get("groupName") or group_name,
                linked_device=c.get("linkedDevice"),
            ))

        total = data.get("totalCount", 0)
        if not total or len(clients) >= total or len(raw_clients) < page_size:
            return clients

    logger.warning(f"Ruijie klientlar sahifalash limiti (guruh {group_id}) - {max_pages} sahifadan keyin to'xtatildi")
    return clients


def get_ruijie_clients(timeout: int = 10) -> List[RuijieClient]:
    """
    Ruijie Cloud'dagi BARCHA filiallar (guruhlar)dan hozir ulangan
    klientlar ro'yxatini oladi. Sozlanmagan yoki xato bo'lsa - bo'sh
    ro'yxat qaytaradi (exception ko'tarmaydi), xuddi UniFi discovery
    naqshiga o'xshab.

    MUHIM: barcha muhit o'zgaruvchilari HAR CHAQIRUVDA dinamik
    o'qiladi (modul darajasidagi "muzlab qolgan" konstanta emas) -
    bu loyihada bir necha marta uchragan xato turkumini oldini oladi.
    """
    base_url = os.getenv("RUIJIE_BASE_URL", "https://cloud.ruijienetworks.com").rstrip("/")
    app_id = os.getenv("RUIJIE_APP_ID", "")
    app_secret = os.getenv("RUIJIE_APP_SECRET", "")
    static_token = os.getenv("RUIJIE_STATIC_TOKEN", DEFAULT_STATIC_TOKEN)

    if not app_id or not app_secret:
        return []

    access_token = _authenticate(base_url, app_id, app_secret, static_token, timeout)
    if not access_token:
        return []

    groups = _get_all_group_ids(base_url, access_token, timeout)
    if not groups:
        logger.warning("Ruijie Cloud'da hech qanday guruh/filial topilmadi")
        return []

    all_clients: List[RuijieClient] = []
    seen_macs = set()
    for group in groups:
        for client in _get_clients_for_group(base_url, access_token, group["id"], group["name"], timeout):
            if client.mac and client.mac in seen_macs:
                continue  # bir xil klient bir nechta guruhda takrorlanmasin
            seen_macs.add(client.mac)
            all_clients.append(client)

    logger.info(f"Ruijie Cloud discovery: {len(groups)} ta guruh, {len(all_clients)} ta klient")
    return all_clients


if __name__ == "__main__":
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(message)s")
    clients = get_ruijie_clients()
    print(f"Jami {len(clients)} ta klient topildi:")
    for c in clients:
        print(f"  {c.mac} | {c.ip or '-'} | {c.group_name} | {'kabel' if c.is_wired else 'wifi'} | {c.manufacturer or '-'}")
