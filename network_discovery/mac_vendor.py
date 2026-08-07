"""
MAC Vendor Lookup - network_discovery paketi.

IEEE'ning rasmiy OUI (Organizationally Unique Identifier) bazasidan
foydalanadi - `ieee-data` paketi orqali (`apt install ieee-data`,
`arp-scan`ning bog'liqligi sifatida ham keladi). Bu **32 000+ haqiqiy
vendor yozuvi**, tarmoqqa chiqmasdan mahalliy qidiriladi (tezkor,
internet talab qilmaydi).
"""
import csv
import logging
import os
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("mac_vendor")

OUI_CSV_PATHS = [
    "/usr/share/ieee-data/oui.csv",
    "/usr/share/nmap/nmap-mac-prefixes",  # muqobil manba (nmap paketi bilan keladi)
]


@lru_cache(maxsize=1)
def _load_oui_table() -> dict:
    """OUI (birinchi 6 hex-belgi) -> vendor nomi lug'atini yuklaydi (bir marta, keshlanadi)."""
    table = {}

    for path in OUI_CSV_PATHS:
        if not os.path.isfile(path):
            continue
        if path.endswith(".csv"):
            with open(path, encoding="utf-8", errors="replace") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    prefix = row.get("Assignment", "").strip().upper()
                    org = row.get("Organization Name", "").strip()
                    if prefix and org:
                        table[prefix] = org
        break  # birinchi topilgan manba yetarli

    logger.info(f"OUI bazasi yuklandi: {len(table)} ta yozuv")
    return table


def lookup_vendor(mac_address: str) -> Optional[str]:
    """
    MAC manzil bo'yicha ishlab chiqaruvchini qaytaradi.
    Masalan: "F4:BD:9E:11:22:33" -> "Cisco Systems, Inc"
    Topilmasa (masalan lokal/tasodifiy generatsiya qilingan MAC -
    "locally administered" biti o'rnatilgan) None qaytaradi.
    """
    if not mac_address:
        return None

    clean = mac_address.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(clean) < 6:
        return None

    oui = clean[:6]
    table = _load_oui_table()
    return table.get(oui)


def is_locally_administered(mac_address: str) -> bool:
    """
    MAC manzilning ikkinchi biti "1" bo'lsa - bu global ro'yxatdan
    o'tgan (haqiqiy zavod) MAC emas, balki qo'lda/virtual mashina/VPN
    tomonidan generatsiya qilingan manzil (masalan Docker, VM,
    tasodifiy MAC). Bunday manzillar uchun OUI qidiruv ma'nosiz.
    """
    try:
        first_octet = int(mac_address.split(":")[0].split("-")[0], 16)
        return bool(first_octet & 0b00000010)
    except (ValueError, IndexError):
        return False
