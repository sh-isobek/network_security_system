"""
Switch SNMP adapteri - kabel orqali ulangan qurilmalar uchun.

Bu adapter standart SNMP MIB-II (`ifAdminStatus`, OID 1.3.6.1.2.1.2.2.1.7)
orqali ishlaydi - bu OID deyarli barcha korporativ switch'larda (Ruijie,
Aruba, TP-Link, Cisco va h.k.) qo'llab-quvvatlanadi, shuning uchun har bir
vendor uchun alohida kod yozish shart emas.

Amalga oshirish usuli: `net-snmp` paketining `snmpset`/`snmpget` CLI
vositalari `subprocess` orqali chaqiriladi. Bu yondashuv Python SNMP
kutubxonalariga (pysnmp) qaraganda ancha barqaror - net-snmp C
kutubxonasiga asoslangan, versiyalararo mos, va production serverlarda
odatda tayyor o'rnatilgan bo'ladi.

O'rnatish:
    sudo apt install snmp

MUHIM: Bu adapter portni **IP/MAC bo'yicha emas, balki port raqami
bo'yicha** boshqaradi (`device.switch_port`, masalan "14" - ifIndex).
IP/MAC'ni port raqamiga bog'lash uchun switch'ning MAC-jadvalini (CAM
table, OID 1.3.6.1.2.1.17.4.3.1.2) so'rash kerak bo'ladi - bu keyingi
kengaytirish sifatida qo'shiladi (vendor tanlangach).

SNMP Write (Set) uchun `community string` **write-huquqli** bo'lishi
shart (odatiy "public" faqat read-only bo'ladi - buni tarmoq
administratori switch tomonida alohida sozlashi kerak).
"""
import os
import subprocess

from response.base_adapter import BlockingAdapter, ActionResult, TargetDevice

SWITCH_HOST = os.getenv("SWITCH_HOST", "")
SNMP_WRITE_COMMUNITY = os.getenv("SNMP_WRITE_COMMUNITY", "private")
SNMP_PORT = os.getenv("SNMP_PORT", "161")

# ifAdminStatus: 1 = up (yoqilgan), 2 = down (o'chirilgan)
IF_ADMIN_STATUS_OID = "1.3.6.1.2.1.2.2.1.7"


class SwitchSNMPAdapter(BlockingAdapter):
    name = "switch_snmp"

    def can_handle(self, device: TargetDevice) -> bool:
        return device.connection_type == "cable" and bool(device.switch_port)

    def _snmpset(self, oid: str, value_type: str, value: str) -> ActionResult:
        if not SWITCH_HOST:
            return ActionResult(False, "SWITCH_HOST sozlanmagan (.env)", self.name)

        cmd = [
            "snmpset", "-v", "2c",
            "-c", SNMP_WRITE_COMMUNITY,
            "-t", "5", "-r", "1",  # timeout=5s, 1 marta qayta urinish
            f"{SWITCH_HOST}:{SNMP_PORT}",
            oid, value_type, value,
        ]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except FileNotFoundError:
            return ActionResult(False, "snmpset topilmadi - 'apt install snmp' bilan o'rnating", self.name)
        except subprocess.TimeoutExpired:
            return ActionResult(False, f"SNMP timeout - {SWITCH_HOST} javob bermadi", self.name)

        if result.returncode == 0:
            return ActionResult(True, f"SNMP muvaffaqiyatli: {result.stdout.strip()}", self.name)
        return ActionResult(False, f"SNMP xatoligi: {result.stderr.strip() or result.stdout.strip()}", self.name)

    def _set_port_status(self, port_index: str, status: int) -> ActionResult:
        res = self._snmpset(f"{IF_ADMIN_STATUS_OID}.{port_index}", "i", str(status))
        if res.success:
            action = "o'chirildi" if status == 2 else "yoqildi"
            res.message = f"Switch port {port_index} muvaffaqiyatli {action}"
        return res

    def disconnect(self, device: TargetDevice) -> ActionResult:
        return self._set_port_status(device.switch_port, status=2)  # down

    def quarantine(self, device: TargetDevice) -> ActionResult:
        # To'liq o'chirish o'rniga alohida "Quarantine VLAN"ga o'tkazish
        # (OID: vendor-specific, masalan Cisco vmVlan 1.3.6.1.4.1.9.9.68.1.2.2.1.2)
        # switch vendor tanlangach qo'shiladi. Hozircha portni o'chirish orqali
        # ekvivalent natija olinadi (qurilma tarmoqqa chiqolmaydi).
        return self.disconnect(device)

    def restore(self, device: TargetDevice) -> ActionResult:
        return self._set_port_status(device.switch_port, status=1)  # up
