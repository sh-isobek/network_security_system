"""
Kerio Control Connection/Host log parser.

MUHIM (real production'da aniqlangan xato - TUZATILDI): bu parserning
avvalgi versiyasi Kerio Control'ning HAQIQIY log formatiga emas, balki
umumiy iptables-uslubidagi (taxminiy) formatga qarab yozilgan edi -
`SRC=... DST=... DPT=... PROTO=...` va `DHCP: Lease granted to ...
MAC=...`. Bu formatlar Kerio Control'da UMUMAN MAVJUD EMAS - hatto
Kerio to'g'ri log kategoriyalarini syslog'ga yuborsa ham, bu parser
ularni hech qachon "tanimasdi" (`can_parse()` doim `False` qaytarardi).

Rasmiy Kerio Control hujjatlari (support.keriocontrol.gfi.com,
manuals.gfi.com) orqali tasdiqlangan HAQIQIY formatlar:

  **Connection log** (aloqa/trafik hodisalari):
      [18/Apr/2013 10:22:47] [ID] 613181 [Rule] NAT [Service] HTTP
      [User] winston [Connection] TCP 192.168.1.140:1193 > hit.google.com:80
      [Duration] 121 sec [Bytes] 1575/1290/2865 [Packets] 5/9/14

  **Host log** (IP/MAC/hostname bog'lanishi - DHCP/host aniqlash):
      [04/Mar/2014 12:07:28] [IPv4] 10.10.30.81 [MAC] 00-0c-29-1d-cc-bd
      (Apple) [Hostname] jsmith-cp

      (ba'zan orasida ixtiyoriy `[IPv6] ...` ham keladi, va oxirida
      "- IPv6 address ... registered/removed" kabi qo'shimcha matn
      bo'lishi mumkin - bularning barchasi IP/MAC/Hostname
      bog'lanishini o'zgartirmaydi, shuning uchun keng qidiruv
      qilinadi).

Kerio Control Administration > Logs > (kerakli log, masalan "Connection"
yoki "Host") > o'ng tugma > Log Settings > External Logging > "Enable
Syslog logging" > Syslog Server = shu serverning manzili:porti orqali
yoqiladi (`docs_KERIO_CONTROL_SETUP.md`ga qarang).

Eslatma: loyiha talabiga ko'ra Kerio Control FAQAT DHCP/host manba
sifatida ishlatiladi (`KerioConnectionParser` shu bilan birga trafik
oqimini ham "Live Map" uchun beradi) - xavfni aniqlash (threat
detection) Suricata zimmasida bo'ladi, bu yerda emas.
"""
import re
from typing import Optional

from parsers.base import BaseParser, ParsedEvent

# Namuna: [Connection] TCP 192.168.1.140:1193 > hit.google.com:80
# Manzil (destination) IP ham, DNS nomi ham bo'lishi mumkin (Kerio DNS
# keshida bo'lsa, IP o'rniga nom ko'rsatadi) - shuning uchun bu qism
# ham raqamli IP, ham domen nomiga mos keladigan keng naqsh bilan olinadi.
_CONNECTION_RE = re.compile(
    r"\[Connection\]\s+(?P<proto>\w+)\s+"
    r"(?P<src>\d{1,3}(?:\.\d{1,3}){3}):(?P<sport>\d+)\s*>\s*"
    r"(?P<dst>[^\s:]+):(?P<dport>\d+)"
)

# Namuna: [IPv4] 10.10.30.81 [MAC] 00-0c-29-1d-cc-bd (Apple) [Hostname] jsmith-cp
# MAC manzil Kerio'da CHIZIQCHA bilan keladi (00-0c-29-...), ikki nuqta
# bilan EMAS - avvalgi versiyada bu ham noto'g'ri edi.
_HOST_RE = re.compile(
    r"\[IPv4\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?:\[IPv6\]\s+\S+\s+)?"
    r"\[MAC\]\s+(?P<mac>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})"
    r"(?:\s*\([^)]*\))?"
    r"\s+\[Hostname\]\s+(?P<host>\S+)"
)


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


class KerioConnectionParser(BaseParser):
    name = "kerio_connection"

    def can_parse(self, raw_message: str) -> bool:
        return "[Connection]" in raw_message

    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        m = _CONNECTION_RE.search(raw_message)
        if not m:
            return None
        dst = m.group("dst")
        return ParsedEvent(
            source_ip=m.group("src"),
            dest_ip=dst if _is_ip(dst) else None,
            dest_domain=None if _is_ip(dst) else dst.rstrip("."),
            dest_port=int(m.group("dport")),
            protocol=m.group("proto").upper(),
            event_type="connection",
        )


class KerioHostParser(BaseParser):
    """IP/MAC/Hostname bog'lanishini (Host log - DHCP/host aniqlash) ajratib oladi."""
    name = "kerio_host"

    def can_parse(self, raw_message: str) -> bool:
        return "[IPv4]" in raw_message and "[MAC]" in raw_message and "[Hostname]" in raw_message

    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        m = _HOST_RE.search(raw_message)
        if not m:
            return None
        return ParsedEvent(
            source_ip=m.group("ip"),
            mac_address=m.group("mac").upper().replace("-", ":"),
            hostname=m.group("host"),
            event_type="dhcp_lease",
        )


# Orqaga moslik uchun eski nom saqlanadi (boshqa joyda import qilingan
# bo'lishi mumkin) - endi Host log formatini o'qiydi.
KerioDHCPParser = KerioHostParser
