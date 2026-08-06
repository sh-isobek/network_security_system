"""
Barcha parser'lar uchun umumiy interfeys.

Har bir yangi log manbai (Kerio, Windows DNS, switch, UniFi) uchun
alohida parser klassi yoziladi va shu interfeysga amal qiladi.
Shu tufayli parser_engine.py hech qaysi manba haqida bilishi shart emas -
u shunchaki ro'yxatdagi parser'larni birma-bir sinab ko'radi.
"""
from abc import ABC, abstractmethod
from typing import Optional, TypedDict


class ParsedEvent(TypedDict, total=False):
    source_ip: str
    dest_ip: Optional[str]
    dest_domain: Optional[str]
    dest_port: Optional[int]
    protocol: Optional[str]
    event_type: str          # "connection" | "dns_query" | ...
    hostname: Optional[str]  # agar log manbaida bo'lsa (masalan Kerio DHCP)
    mac_address: Optional[str]


class BaseParser(ABC):
    name: str = "base"

    @abstractmethod
    def can_parse(self, raw_message: str) -> bool:
        """Ushbu xabar shu parser formatiga mos keladimi - tez tekshiruv."""
        raise NotImplementedError

    @abstractmethod
    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        """Xabarni structured ma'lumotga aylantiradi. Mos kelmasa None qaytaradi."""
        raise NotImplementedError
