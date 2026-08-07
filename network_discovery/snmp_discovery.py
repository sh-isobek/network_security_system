"""
SNMP Discovery - network_discovery paketi.

`snmpget`/`snmpwalk` (net-snmp) CLI vositalari orqali ishlaydi -
`response/switch_adapter.py`dagi bilan bir xil, sinovdan o'tgan
yondashuv (pysnmp Python 3.12 bilan mos kelmagani sababli).

Standart MIB-II OID'lari orqali qurilma haqida asosiy ma'lumot
olinadi - bu deyarli barcha SNMP-qo'llab-quvvatlaydigan qurilmalarda
(switch, printer, UPS, router) ishlaydi, vendor-specific MIB shart
emas.
"""
import logging
import subprocess
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("snmp_discovery")

OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"


@dataclass
class SnmpDeviceInfo:
    ip: str
    sys_descr: Optional[str] = None
    sys_name: Optional[str] = None
    sys_object_id: Optional[str] = None
    sys_location: Optional[str] = None
    device_type_guess: Optional[str] = None  # sys_descr matniga qarab taxminiy tur


def _snmp_get(ip: str, oid: str, community: str = "public", timeout: int = 3, port: int = 161) -> Optional[str]:
    try:
        result = subprocess.run(
            ["snmpget", "-v2c", "-c", community, "-t", str(timeout), "-r", "1", "-Oqv", f"{ip}:{port}", oid],
            capture_output=True, text=True, timeout=timeout + 3,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None

    if result.returncode != 0:
        return None
    value = result.stdout.strip().strip('"')
    return value or None


def _guess_device_type(sys_descr: str) -> str:
    if not sys_descr:
        return "unknown"
    lower = sys_descr.lower()
    if any(k in lower for k in ["cisco ios", "switch", "catalyst"]):
        return "switch"
    if any(k in lower for k in ["router", "routeros", "mikrotik"]):
        return "router"
    if any(k in lower for k in ["printer", "laserjet", "officejet"]):
        return "printer"
    if any(k in lower for k in ["ups", "apc", "smart-ups"]):
        return "ups"
    if any(k in lower for k in ["linux", "windows", "unix"]):
        return "server"
    return "unknown"


def snmp_discover(ip: str, community: str = "public", timeout: int = 3, port: int = 161) -> Optional[SnmpDeviceInfo]:
    """
    Berilgan IP'dan SNMP orqali asosiy ma'lumotni oladi. Agar SNMP
    javob bermasa (o'chirilgan yoki community noto'g'ri), `None`
    qaytaradi - xatoni "topilmadi" sifatida talqin qilish kerak,
    tarmoq nosozligi emas.
    """
    sys_descr = _snmp_get(ip, OID_SYS_DESCR, community, timeout, port)
    if sys_descr is None:
        return None  # SNMP umuman javob bermadi

    return SnmpDeviceInfo(
        ip=ip,
        sys_descr=sys_descr,
        sys_name=_snmp_get(ip, OID_SYS_NAME, community, timeout, port),
        sys_object_id=_snmp_get(ip, OID_SYS_OBJECT_ID, community, timeout, port),
        sys_location=_snmp_get(ip, OID_SYS_LOCATION, community, timeout, port),
        device_type_guess=_guess_device_type(sys_descr),
    )
