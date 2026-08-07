"""
Active Directory Discovery - network_discovery paketi.

`ldap3` orqali (dashboard/ldap_auth.py bilan bir xil kutubxona) AD/LDAP
serveridan "computer" obyektlarini so'raydi. Standart AD sxemasida
kompyuterlar `objectClass=computer` bilan belgilanadi va `dNSHostName`,
`operatingSystem` kabi atributlarga ega.
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

from ldap3 import Server, Connection, ALL, SIMPLE

logger = logging.getLogger("ad_discovery")

AD_SERVER = os.getenv("AD_SERVER", os.getenv("LDAP_SERVER", ""))
AD_BASE_DN = os.getenv("AD_BASE_DN", os.getenv("LDAP_BASE_DN", ""))
AD_SERVICE_DN = os.getenv("AD_SERVICE_DN", os.getenv("LDAP_SERVICE_DN", ""))
AD_SERVICE_PASSWORD = os.getenv("AD_SERVICE_PASSWORD", os.getenv("LDAP_SERVICE_PASSWORD", ""))
# Standart Active Directory filtri. Boshqa LDAP serverlar (masalan
# umumiy OpenLDAP) uchun moslashtiring - masalan `(objectClass=device)`
AD_COMPUTER_FILTER = os.getenv("AD_COMPUTER_FILTER", "(objectClass=computer)")


@dataclass
class AdComputer:
    name: str
    dns_hostname: Optional[str] = None
    operating_system: Optional[str] = None
    distinguished_name: Optional[str] = None


def discover_ad_computers(timeout: int = 10) -> List[AdComputer]:
    """
    AD/LDAP serveridan kompyuterlar ro'yxatini oladi. Server sozlanmagan
    yoki ulanib bo'lmasa, bo'sh ro'yxat qaytaradi (exception ko'tarmaydi).
    """
    if not AD_SERVER or not AD_BASE_DN:
        logger.warning("AD_SERVER/AD_BASE_DN sozlanmagan")
        return []

    try:
        server = Server(AD_SERVER, get_info=ALL, connect_timeout=timeout)
        conn = Connection(
            server, user=AD_SERVICE_DN, password=AD_SERVICE_PASSWORD,
            authentication=SIMPLE, auto_bind=True,
        )
        conn.search(
            AD_BASE_DN, AD_COMPUTER_FILTER,
            attributes=["cn", "dNSHostName", "operatingSystem", "name"],
        )

        computers = []
        for entry in conn.entries:
            name = str(entry.cn) if hasattr(entry, "cn") and entry.cn else str(entry.entry_dn)
            computers.append(AdComputer(
                name=name,
                dns_hostname=str(entry.dNSHostName) if hasattr(entry, "dNSHostName") and entry.dNSHostName else None,
                operating_system=str(entry.operatingSystem) if hasattr(entry, "operatingSystem") and entry.operatingSystem else None,
                distinguished_name=entry.entry_dn,
            ))

        conn.unbind()
        logger.info(f"AD Discovery: {len(computers)} ta kompyuter topildi")
        return computers

    except Exception as exc:
        logger.error(f"AD/LDAP'ga ulanib bo'lmadi: {exc}")
        return []
