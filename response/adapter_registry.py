"""
Adapter Registry - qaysi qurilma uchun qaysi bloklash adapteri
ishlatilishini hal qiladi.

Tanlash mantig'i (TZ'dagi qarorga mos):
  - connection_type == "wifi"  -> UniFiAdapter
  - connection_type == "cable" -> SwitchSNMPAdapter
  - aniqlanmagan holat          -> MockAdapter (faqat test/demo uchun;
                                    production'da bu holatda alert
                                    "action_taken"da ogohlantirish qoladi)
"""
from response.base_adapter import TargetDevice, ActionResult
from response.unifi_adapter import UniFiAdapter
from response.switch_adapter import SwitchSNMPAdapter
from response.mock_adapter import MockAdapter

_ADAPTERS = [
    UniFiAdapter(),
    SwitchSNMPAdapter(),
]

# MockAdapter faqat DEMO_MODE=true bo'lganda ro'yxatga qo'shiladi
import os
if os.getenv("DEMO_MODE", "false").lower() == "true":
    _ADAPTERS.append(MockAdapter())


def get_adapter(device: TargetDevice):
    for adapter in _ADAPTERS:
        if adapter.can_handle(device):
            return adapter
    return None


def quarantine_device(device: TargetDevice) -> ActionResult:
    adapter = get_adapter(device)
    if adapter is None:
        return ActionResult(
            False,
            f"Mos adapter topilmadi (connection_type={device.connection_type}) - qo'lda tekshirish kerak",
            "none",
        )
    return adapter.quarantine(device)
