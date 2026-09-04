"""
Kerio Control Connection/Host log parser.

MUHIM (real production'da IKKI MARTA aniqlangan xato - TUZATILDI):

1-marta: bu parserning eng avvalgi versiyasi Kerio Control'ning
HAQIQIY log formatiga emas, balki umumiy iptables-uslubidagi
(taxminiy) formatga qarab yozilgan edi - `SRC=... DST=... DPT=...
PROTO=...` va `DHCP: Lease granted to ... MAC=...`. Bu formatlar
Kerio Control'da UMUMAN MAVJUD EMAS.

2-marta: birinchi tuzatish RASMIY Kerio hujjatidagi (2013-yilgi,
eski versiya) namunaga asoslangan edi: `TCP 192.168.1.140:1193 >
hit.google.com:80`. Lekin HAQIQIY production Kerio Control (yangiroq
versiya) BUTUNLAY BOSHQA formatda yozadi - manzil endi doim
`hostname (ip):port` ko'rinishida (agar teskari DNS nomi mavjud
bo'lsa) va ajratuvchi `>` emas, `->` (chiziqcha bilan):

    [Connection] TCP sph-262.synergypharm.org (172.16.1.35):63579 ->
    lr-in-f95.1e100.net (209.85.233.95):443 [Iface] WAN0_Uztelecom
    [Duration] 31 sec [Bytes] 1458/9404/10862 [Packets] 8/10/18

Bu **HAQIQIY, production'dan olingan** namuna - hujjatdagi emas.
Parser endi ikkalasini ham (eski `>` va yangi `->` ajratuvchi,
`ip:port` va `hostname (ip):port` ikkala manzil shakli) qo'llab-
quvvatlaydi - Kerio Control versiyasi/sozlamasiga qarab farq qilishi
mumkinligi uchun.

  **Host log** (IP/MAC/hostname bog'lanishi - DHCP/host aniqlash):
      [04/Mar/2014 12:07:28] [IPv4] 10.10.30.81 [MAC] 00-0c-29-1d-cc-bd
      (Apple) [Hostname] jsmith-cp

      MUHIM: `[Hostname]` HAR DOIM ham kelmaydi (masalan "IP address
      leased from DHCP" ko'pincha faqat `[IPv4]`+`[MAC]` bilan keladi,
      "User logged in"/"Host registered" esa ba'zan `[MAC]`SIZ ham
      keladi) - shuning uchun `[MAC]` majburiy, `[Hostname]` ixtiyoriy
      qilib olinadi (avvalgi versiyada ikkalasi ham majburiy edi -
      bu ko'p haqiqiy yozuvni "tanimasdan" o'tkazib yuborardi).

Kerio Control Administration > Logs > (kerakli log, masalan "Connection"
yoki "Host") > o'ng tugma > Log Settings > External Logging > "Enable
Syslog logging" > Syslog Server = shu serverning manzili:porti orqali
yoqiladi. Connection log uchun BUNDAN OLDIN yana bir qadam kerak:
Configuration > Traffic Rules > kerakli qoidaning Action katakchasida
"Log connections"ni yoqish (aks holda Kerio'ning o'zi HECH QANDAY
ulanishni qayd etmaydi - syslog'ga aloqasi yo'q). Barchasi
`docs_KERIO_CONTROL_SETUP.md`da batafsil.

Eslatma: loyiha talabiga ko'ra Kerio Control FAQAT DHCP/host manba
sifatida ishlatiladi (`KerioConnectionParser` shu bilan birga trafik
oqimini ham "Live Map" uchun beradi) - xavfni aniqlash (threat
detection) Suricata zimmasida bo'ladi, bu yerda emas.
"""
import re
from typing import Optional

from parsers.base import BaseParser, ParsedEvent

# Bitta manzil qismi ("hostname (ip):port" YOKI "ip:port" YOKI
# "hostname:port" - agar teskari DNS nomi bo'lmasa) - src HAM, dst HAM
# shu shaklda kelishi mumkin.
_ENDPOINT_RE = re.compile(
    r"(?:(?P<host>\S+)\s+\((?P<ip>\d{1,3}(?:\.\d{1,3}){3})\)|(?P<plain>[^\s:]+)):(?P<port>\d+)"
)

# Namuna (HAQIQIY, production'dan): [Connection] TCP sph-262.synergypharm.org
# (172.16.1.35):63579 -> lr-in-f95.1e100.net (209.85.233.95):443 [Iface] ...
# Eski (2013-yilgi hujjat) format ham qabul qilinadi: `TCP 192.168.1.140:1193
# > hit.google.com:80` - shuning uchun ajratuvchi ixtiyoriy chiziqcha bilan
# (`-?>`), va manzil qismlari alohida `_ENDPOINT_RE` orqali tahlil qilinadi.
_CONNECTION_RE = re.compile(
    r"\[Connection\]\s+(?P<proto>\w+)\s+(?P<srcpart>.+?)\s*-?>\s*(?P<dstpart>.+?)(?:\s+\[|$)"
)

# Namuna: [IPv4] 10.10.30.81 [MAC] 00-0c-29-1d-cc-bd (Apple) [Hostname] jsmith-cp
# MAC manzil Kerio'da CHIZIQCHA bilan keladi (00-0c-29-...), ikki nuqta
# bilan EMAS - avvalgi versiyada bu ham noto'g'ri edi. [Hostname] IXTIYORIY
# (yuqoridagi modul izohiga qarang).
_HOST_RE = re.compile(
    r"\[IPv4\]\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?:\[IPv6\]\s+\S+\s+)?"
    r"\[MAC\]\s+(?P<mac>[0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})"
    r"(?:\s*\([^)]*\))?"
    r"(?:\s+\[Hostname\]\s+(?P<host>\S+))?"
)


def _is_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _parse_endpoint(part: str):
    """`"hostname (ip):port"`/`"ip:port"`/`"hostname:port"`ni (ip_yoki_None,
    domen_yoki_None, port) qilib ajratadi."""
    m = _ENDPOINT_RE.match(part.strip())
    if not m:
        return None, None, None
    port = int(m.group("port"))
    if m.group("ip"):
        return m.group("ip"), None, port
    plain = m.group("plain")
    if _is_ip(plain):
        return plain, None, port
    return None, plain.rstrip("."), port


class KerioConnectionParser(BaseParser):
    name = "kerio_connection"

    def can_parse(self, raw_message: str) -> bool:
        return "[Connection]" in raw_message

    def parse(self, raw_message: str) -> Optional[ParsedEvent]:
        m = _CONNECTION_RE.search(raw_message)
        if not m:
            return None
        src_ip, _src_domain, _sport = _parse_endpoint(m.group("srcpart"))
        dst_ip, dst_domain, dport = _parse_endpoint(m.group("dstpart"))
        if not src_ip or not dport:
            return None
        return ParsedEvent(
            source_ip=src_ip,
            dest_ip=dst_ip,
            dest_domain=dst_domain,
            dest_port=dport,
            protocol=m.group("proto").upper(),
            event_type="connection",
        )


class KerioHostParser(BaseParser):
    """IP/MAC/Hostname bog'lanishini (Host log - DHCP/host aniqlash) ajratib oladi."""
    name = "kerio_host"

    def can_parse(self, raw_message: str) -> bool:
        return "[IPv4]" in raw_message and "[MAC]" in raw_message

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
