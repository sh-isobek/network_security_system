"""
Windows Server DNS (AD-integratsiyalashgan) so'rovlarini o'qiydigan parser.

MUHIM: Windows o'zi syslog protokolini bilmaydi, shuning uchun DNS
serveridan loglarni olish uchun oraliq agent kerak (masalan NXLog yoki
Snare). Windows DNS Server'da "Analytical" (Event ID 256 = so'rov,
257 = javob) yoki debug-log yoqilib, NXLog orqali JSON ko'rinishida
bizning syslog collector'ga (0-bosqichda qurilgan) UDP orqali yuboriladi.

Kutilayotgan JSON format (NXLog om_udp konfiguratsiyasi shu ko'rinishda
sozlanishi kerak):

    {
      "EventID": 256,
      "ClientIP": "172.16.2.30",
      "QueryName": "malicious-domain.com",
      "QueryType": "A",
      "Timestamp": "2026-07-30T13:05:00Z"
    }

NXLog namuna konfiguratsiyasi README_NXLOG.md faylida keltirilgan.
"""
import json
from typing import Optional

from parsers.base import BaseParser, ParsedEvent

# Faqat DNS so'rov event'lari (256) qiziqtiradi - javoblar (257) hozircha kerak emas
_DNS_QUERY_EVENT_ID = 256


class WindowsDNSParser(BaseParser):
    name = "windows_dns"

    def can_parse(self, raw_message: str) -> bool:
        stripped = raw_message.strip()
        return stripped.startswith("{") and '"QueryName"' in stripped

    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        try:
            data = json.loads(raw_message.strip())
        except (json.JSONDecodeError, ValueError):
            return None

        if data.get("EventID") != _DNS_QUERY_EVENT_ID:
            return None

        client_ip = data.get("ClientIP")
        query_name = data.get("QueryName")
        if not client_ip or not query_name:
            return None

        return ParsedEvent(
            source_ip=client_ip,
            dest_ip=None,
            dest_domain=query_name.rstrip("."),
            dest_port=53,
            protocol="DNS",
            event_type="dns_query",
        )
