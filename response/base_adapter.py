"""
Bloklash/Karantin Adapterlari uchun umumiy interfeys - 5-bosqich.

Nega abstraksiya kerak: qurilma Wi-Fi (UniFi) yoki kabel (switch) orqali
ulangan bo'lishi mumkin, va switch turi (Ruijie/Aruba/TP-Link) ham
farq qiladi. response_engine.py bu farqlar bilan ishlashi shart emas -
u faqat `adapter.quarantine(device)` deb chaqiradi, qaysi adapter
tanlanishini `AdapterRegistry` hal qiladi.

Har bir adapter 3 ta harakatni qo'llab-quvvatlashga harakat qiladi:
  - disconnect(device)  : ulanishni darhol uzish
  - quarantine(device)  : alohida "Quarantine VLAN"ga o'tkazish
                           (to'liq uzishdan ko'ra yumshoqroq - IT xodimi
                           tekshirguncha internetga chiqolmaydi, lekin
                           tarmoqda "ko'rinadi")
  - restore(device)     : administrator qo'lda yoki avtomatik tasdiqlagach
                           qurilmani asl holatga qaytarish
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Optional


@dataclass
class ActionResult:
    success: bool
    message: str
    adapter_name: str


@dataclass
class TargetDevice:
    ip_address: str
    mac_address: Optional[str] = None
    connection_type: Optional[str] = None   # "wifi" | "cable" | "unknown"
    switch_port: Optional[str] = None        # agar ma'lum bo'lsa (masalan "Gi0/14")


class BlockingAdapter(ABC):
    name: str = "base"

    @abstractmethod
    def can_handle(self, device: TargetDevice) -> bool:
        """Ushbu adapter shu qurilma turini boshqara oladimi (wifi/cable)."""
        raise NotImplementedError

    @abstractmethod
    def disconnect(self, device: TargetDevice) -> ActionResult:
        raise NotImplementedError

    @abstractmethod
    def quarantine(self, device: TargetDevice) -> ActionResult:
        raise NotImplementedError

    @abstractmethod
    def restore(self, device: TargetDevice) -> ActionResult:
        raise NotImplementedError
