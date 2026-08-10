"""
Virtualizatsiya Host Discovery (VMware ESXi, Hyper-V) - network_discovery paketi.

HALOL CHEKLOV: bu loyiha tayyorlangan sandbox muhitida haqiqiy
ESXi/vCenter yoki Hyper-V server mavjud emas - shuning uchun bu modul
`response/unifi_adapter.py` va `network_discovery/unifi_discovery.py`
bilan bir xil andozada yozilgan: real API chaqiruvlari to'g'ri
qurilgan, lekin xatoni yashirmasdan **graceful fail** qiladi (bo'sh
ro'yxat qaytaradi, exception ko'tarmaydi) - bu xatti-harakat real
testda tasdiqlangan.
"""
import logging
import os
from dataclasses import dataclass
from typing import List, Optional

import requests

logger = logging.getLogger("virtualization_discovery")

ESXI_HOST = os.getenv("ESXI_HOST", "")           # yoki vCenter manzili
ESXI_USERNAME = os.getenv("ESXI_USERNAME", "")
ESXI_PASSWORD = os.getenv("ESXI_PASSWORD", "")

HYPERV_HOST = os.getenv("HYPERV_HOST", "")
HYPERV_USERNAME = os.getenv("HYPERV_USERNAME", "")
HYPERV_PASSWORD = os.getenv("HYPERV_PASSWORD", "")


@dataclass
class VirtualMachine:
    name: str
    ip: Optional[str] = None
    power_state: Optional[str] = None
    guest_os: Optional[str] = None
    hypervisor: str = "unknown"  # "esxi" | "hyperv"


def discover_esxi_vms(timeout: int = 15) -> List[VirtualMachine]:
    """
    VMware ESXi/vCenter REST API (`/rest/vcenter/vm`) orqali VM
    ro'yxatini oladi. To'liq ishlaydigan integratsiya uchun rasmiy
    `pyvmomi` kutubxonasi tavsiya etiladi (murakkabroq, lekin to'liq
    imkoniyat beradi) - bu yerda soddaroq REST API yondashuvi
    ko'rsatilgan.
    """
    if not ESXI_HOST or not ESXI_USERNAME:
        logger.warning("ESXI_HOST/ESXI_USERNAME sozlanmagan")
        return []

    try:
        session = requests.Session()
        auth_resp = session.post(
            f"https://{ESXI_HOST}/rest/com/vmware/cis/session",
            auth=(ESXI_USERNAME, ESXI_PASSWORD),
            verify=False, timeout=timeout,
        )
        if auth_resp.status_code != 200:
            logger.error(f"ESXi autentifikatsiya muvaffaqiyatsiz: HTTP {auth_resp.status_code}")
            return []

        vm_resp = session.get(f"https://{ESXI_HOST}/rest/vcenter/vm", verify=False, timeout=timeout)
        if vm_resp.status_code != 200:
            logger.error(f"ESXi VM ro'yxatini olib bo'lmadi: HTTP {vm_resp.status_code}")
            return []

        vms_raw = vm_resp.json().get("value", [])
        vms = [
            VirtualMachine(
                name=vm.get("name", "unknown"),
                power_state=vm.get("power_state"),
                hypervisor="esxi",
            )
            for vm in vms_raw
        ]
        logger.info(f"ESXi discovery: {len(vms)} ta VM topildi")
        return vms

    except requests.RequestException as exc:
        logger.error(f"ESXi/vCenter'ga ulanib bo'lmadi: {exc}")
        return []


def discover_hyperv_vms(timeout: int = 15) -> List[VirtualMachine]:
    """
    Hyper-V uchun standart usul - WinRM orqali PowerShell
    (`Get-VM`) buyrug'ini masofadan bajarish. Bu yerda `pywinrm`
    kutubxonasi ishlatiladi (agar o'rnatilgan bo'lsa) - yo'q bo'lsa
    graceful fail.
    """
    if not HYPERV_HOST or not HYPERV_USERNAME:
        logger.warning("HYPERV_HOST/HYPERV_USERNAME sozlanmagan")
        return []

    try:
        import winrm
    except ImportError:
        logger.error("'pywinrm' kutubxonasi o'rnatilmagan - 'pip install pywinrm' bilan qo'shing")
        return []

    try:
        session = winrm.Session(HYPERV_HOST, auth=(HYPERV_USERNAME, HYPERV_PASSWORD))
        result = session.run_ps(
            "Get-VM | Select-Object Name,State,@{N='IP';E={($_.NetworkAdapters.IPAddresses -join ',')}} | ConvertTo-Json"
        )
        if result.status_code != 0:
            logger.error(f"Hyper-V PowerShell xatoligi: {result.std_err}")
            return []

        import json
        vms_raw = json.loads(result.std_out)
        if isinstance(vms_raw, dict):
            vms_raw = [vms_raw]

        vms = [
            VirtualMachine(name=vm.get("Name"), power_state=vm.get("State"), hypervisor="hyperv")
            for vm in vms_raw
        ]
        logger.info(f"Hyper-V discovery: {len(vms)} ta VM topildi")
        return vms

    except Exception as exc:
        logger.error(f"Hyper-V'ga ulanib bo'lmadi: {exc}")
        return []
