"""
Mock Adapter - haqiqiy UniFi/switch ulanmaganda pipeline mantig'ini
tekshirish uchun (unit test va demo maqsadida). Production'da bu adapter
ishlatilmaydi - faqat UniFiAdapter va SwitchSNMPAdapter ishlaydi.
"""
from response.base_adapter import BlockingAdapter, ActionResult, TargetDevice


class MockAdapter(BlockingAdapter):
    name = "mock"

    def can_handle(self, device: TargetDevice) -> bool:
        return device.connection_type == "unknown" or device.connection_type is None

    def disconnect(self, device: TargetDevice) -> ActionResult:
        return ActionResult(True, f"[MOCK] {device.ip_address} uzildi (simulyatsiya)", self.name)

    def quarantine(self, device: TargetDevice) -> ActionResult:
        return ActionResult(True, f"[MOCK] {device.ip_address} karantinga o'tkazildi (simulyatsiya)", self.name)

    def restore(self, device: TargetDevice) -> ActionResult:
        return ActionResult(True, f"[MOCK] {device.ip_address} tiklandi (simulyatsiya)", self.name)
