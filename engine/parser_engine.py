"""
Parser Engine - 1-bosqichning yuragi.

Vazifasi:
  1. `raw_logs` jadvalidan processed=False bo'lgan yozuvlarni oladi.
  2. Ro'yxatdagi har bir parser'ni ('can_parse') sinab ko'radi, mos kelgani
     bilan xabarni structured ma'lumotga aylantiradi.
  3. Natijaga qarab:
       - DHCP lease bo'lsa -> devices jadvalini yangilaydi (IP/MAC/hostname)
       - connection/dns_query bo'lsa -> events jadvaliga yozadi,
         devices jadvalidagi last_seen'ni yangilaydi
       - agar dns_query/connection'dagi IP/domen blacklist'da bo'lsa
         (domen bo'lsa - ota-domen ierarxiyasi bo'yicha ham, masalan
         `evil.com` blacklist'da bo'lsa `cdn.evil.com` ham mos keladi -
         `threat_intel/url_intel.py`ga qarang) -> alerts jadvaliga
         yozuv qo'shadi (bloklash 5-bosqichda ulanadi)
       - blacklist'da yo'q, lekin domen nomi fishing'ga o'xshasa
         (leksik evristika, `threat_intel/url_intel.py::lexical_risk_
         score()`) -> alohida, konservativ (faqat eng yuqori darajada)
         Alert
  4. Yozuvni processed=True qilib belgilaydi.

Ishga tushirish (doimiy tsikl sifatida, masalan systemd/cron orqali):
    python -m engine.parser_engine --loop
Yoki bir martalik ishga tushirish (mavjud navbatni tozalash):
    python -m engine.parser_engine
"""
import argparse
import ipaddress
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import RawLog, Device, Event, WebAccessLog, Alert, WhitelistEntry, BlacklistEntry, utcnow
from parsers.kerio_parser import KerioConnectionParser, KerioDHCPParser
from parsers.windows_dns_parser import WindowsDNSParser
from threat_intel.url_intel import domain_parent_candidates, is_punycode, lexical_risk_score

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("parser_engine")

# Yangi manba qo'shilsa, shu ro'yxatga bitta qator qo'shish kifoya
PARSERS = [
    KerioDHCPParser(),
    KerioConnectionParser(),
    WindowsDNSParser(),
]

BATCH_SIZE = 200


def _is_whitelisted(session, value: str) -> bool:
    if not value:
        return False
    return session.query(WhitelistEntry).filter(WhitelistEntry.value == value).first() is not None


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_blacklisted(session, value: str):
    """
    MUHIM (foydalanuvchi chuqur tahlilidagi ⑪-band): avval FAQAT aniq
    moslik (`BlacklistEntry.value == value`) tekshirilardi. Masalan
    blacklist'da `evil.com` bo'lsa-yu, haqiqiy trafik `cdn.login.
    evil.com`ga borsa - bu HECH QACHON aniqlanmasdi. Endi domen
    bo'lsa (IP EMAS), ota-domen ierarxiyasi ham (`login.evil.com`,
    `evil.com`, ... - LABEL chegaralari bo'yicha, `db.device_identity`
    kabi boshqa joylarda ham qo'llanilgan "aniq, xavfsiz" yondashuv)
    tekshiriladi - `threat_intel/url_intel.py::domain_parent_
    candidates()`ga qarang (oddiy `endswith()` EMAS - bu
    `"notevil.com".endswith("evil.com")` kabi soxta moslikka olib
    kelardi).

    IP manzillar uchun xatti-harakat O'ZGARMAYDI (faqat aniq moslik -
    CIDR blacklist bu bosqichda YO'Q, alohida masala).
    """
    if not value:
        return None
    hit = session.query(BlacklistEntry).filter(BlacklistEntry.value == value).first()
    if hit or _is_ip(value):
        return hit
    for candidate in domain_parent_candidates(value)[1:]:  # [0] - value'ning o'zi, yuqorida allaqachon tekshirildi
        hit = session.query(BlacklistEntry).filter(BlacklistEntry.value == candidate).first()
        if hit:
            return hit
    return None


_LEXICAL_ALERT_TAG = "[LEXICAL_PHISHING]"


def _check_lexical_phishing_alert(session, event, device, domain: str, source_ip: str):
    """
    Foydalanuvchi chuqur tahlilidagi ⑦/⑧-band: hali BlacklistEntry'da
    yo'q, lekin nomi bo'yicha fishing'ga o'xshab ko'ringan domen
    (masalan "microsoft-login-security.xyz") uchun ham signal berish.

    MUHIM (halol, ataylab konservativ): bu FAQAT leksik evristika -
    haqiqiy threat-intel tasdiqlash EMAS, shuning uchun soxta-pozitiv
    xavfi bor. Shu sabab Alert FAQAT eng yuqori ("malicious", ballar
    >=71) darajada yaratiladi - pastroq darajalar ("suspicious"/"high")
    hozircha alert QILMAYDI (kelajakda, boshqa signallar bilan
    birlashtirilganda qayta ko'rib chiqilishi mumkin - `CLAUDE.md`ga
    qarang). Bir xil domen uchun QAYTA-QAYTA alert yaratilmasligi
    uchun (masalan minutiga o'nlab DNS so'rovi bo'lishi mumkin),
    `_LEXICAL_ALERT_TAG` + domen orqali oldindan mavjudligi tekshiriladi.
    """
    if not domain or _is_ip(domain):
        return
    if _is_whitelisted(session, domain):
        return

    result = lexical_risk_score(domain)
    if result["level"] != "malicious":
        return

    marker = f"{_LEXICAL_ALERT_TAG} domen={domain}"
    already_alerted = session.query(Alert).filter(Alert.reason.like(f"%{marker}%")).first()
    if already_alerted:
        return

    reasons_text = "; ".join(result["reasons"]) or "yuqori leksik xavf balli"
    alert = Alert(
        event_id=event.id if event else None,
        device_id=device.id if device else None,
        severity="medium",
        reason=(
            f"Fishing'ga o'xshash domen nomi aniqlandi: {domain} "
            f"(ball: {result['score']}/100) - {reasons_text} | {marker}"
        ),
        action_taken="Leksik evristika - haqiqiy threat-intel tasdiqlanmagan, faqat kuzatish uchun",
        notified=False,
    )
    session.add(alert)
    logger.warning(f"LEXICAL PHISHING ALERT: {source_ip} -> {domain} (ball: {result['score']})")


def _upsert_device(session, ip: str, mac: str = None, hostname: str = None, source: str = "unknown"):
    """
    MUHIM (real production xatosi tuzatilgan): avval faqat `ip_address`
    bo'yicha qidirilardi - DHCP muhitida bir xil fizik qurilma (bir xil
    MAC) qayta ulanganda ko'pincha YANGI IP oladi, va bu funksiya buni
    "yangi qurilma" deb yaratib yuborardi (eski IP'dagi qator esa
    "oflayn" bo'lib qolaverardi) - vaqt o'tishi bilan `devices` jadvali
    haqiqiy qurilmalar sonidan ancha ko'p, duplikat qatorlar bilan
    to'lib boradi edi. Endi `db.device_identity.find_or_create_device`
    orqali avval MAC bo'yicha qidiriladi (batafsil: shu modul docstring'i).
    """
    from db.device_identity import find_or_create_device
    return find_or_create_device(session, ip, mac=mac, source=source, hostname=hostname)


def process_one(session, raw_log: RawLog):
    parsed = None
    used_parser = None
    for parser in PARSERS:
        try:
            if parser.can_parse(raw_log.raw_message):
                parsed = parser.parse(raw_log.raw_message)
                if parsed:
                    used_parser = parser.name
                    break
        except Exception as exc:
            logger.warning(f"{parser.name} xatolik berdi: {exc}")

    if parsed is None:
        # Hech qaysi parser tanimadi - keyinchalik tahlil uchun processed=True
        # qilib qo'yamiz, lekin "unparsed" deb belgilashimiz ham mumkin edi.
        raw_log.processed = True
        return

    event_type = parsed.get("event_type")

    if event_type == "dhcp_lease":
        _upsert_device(
            session,
            ip=parsed["source_ip"],
            mac=parsed.get("mac_address"),
            hostname=parsed.get("hostname"),
            source="kerio_dhcp",
        )
        raw_log.processed = True
        return

    # connection yoki dns_query
    device = _upsert_device(session, ip=parsed["source_ip"], source=used_parser)

    event = Event(
        device_id=device.id,
        source_ip=parsed["source_ip"],
        dest_ip=parsed.get("dest_ip"),
        dest_domain=parsed.get("dest_domain"),
        dest_port=parsed.get("dest_port"),
        protocol=parsed.get("protocol"),
        raw_log_id=raw_log.id,
    )
    session.add(event)
    session.flush()

    # DNS query ham sayt/domen faoliyati sifatida alohida indekslanadi.
    # Bu Zeek HTTP/TLS yo'q bo'lgan tarmoqlarda ham dashboard orqali
    # "qaysi IP qaysi domenni qachon so'ragan" qidiruvini beradi.
    if event_type == "dns_query" and parsed.get("dest_domain"):
        session.add(WebAccessLog(
            timestamp=event.timestamp, device_id=device.id,
            source_ip=parsed["source_ip"], dest_ip=parsed.get("dest_ip"),
            domain=str(parsed["dest_domain"]).rstrip(".").lower(),
            url=f"dns://{str(parsed['dest_domain']).rstrip('.').lower()}",
            protocol="DNS", source=used_parser or "dns",
        ))

    # MUHIM (real production'da aniqlangan bo'shliq): Kerio Connection
    # loglari ham "sayt faoliyati" - lekin avval FAQAT dns_query
    # yozuvlari WebAccessLog'ga tushardi. Zeek/NXLog (DNS query
    # domenlari) hali sozlanmagan muhitlarda bu "Saytlar tarixi"
    # sahifasini BUTUNLAY bo'sh qoldirgan edi, garchi Kerio orqali
    # yuz minglab haqiqiy ulanish kelayotgan bo'lsa ham. Endi
    # Connection hodisalari ham (domen bo'lsa domen bilan, aks holda
    # IP bilan) qayd etiladi.
    if event_type == "connection" and (parsed.get("dest_domain") or parsed.get("dest_ip")):
        target_domain = (str(parsed["dest_domain"]).rstrip(".").lower()
                          if parsed.get("dest_domain") else None)
        session.add(WebAccessLog(
            timestamp=event.timestamp, device_id=device.id,
            source_ip=parsed["source_ip"], dest_ip=parsed.get("dest_ip"),
            domain=target_domain or parsed.get("dest_ip"),
            url=None, protocol=parsed.get("protocol") or "TCP",
            status_code=None, source=used_parser or "kerio_connection",
        ))

    if event_type == "dns_query":
        target = parsed.get("dest_domain")
        if _is_whitelisted(session, target):
            logger.debug(f"Whitelist: {target} - o'tkazib yuborildi")
        else:
            bl_hit = _is_blacklisted(session, target)
            if bl_hit:
                alert = Alert(
                    event_id=event.id,
                    device_id=device.id,
                    severity="high",
                    reason=f"Blacklist'dagi domenga so'rov: {target} (manba: {bl_hit.source})",
                    action_taken="TODO: bloklash backend hali ulanmagan (5-bosqich)",
                    notified=False,
                )
                session.add(alert)
                logger.warning(f"ALERT: {parsed['source_ip']} -> {target} (blacklist)")
            else:
                # ⑦/⑧-band: blacklist'da yo'q, lekin nomi bo'yicha
                # fishing'ga o'xshash domen (batafsil: yuqoridagi
                # _check_lexical_phishing_alert() docstring'i).
                _check_lexical_phishing_alert(session, event, device, target, parsed["source_ip"])

    # MUHIM (real production'da aniqlangan bo'shliq): "connection"
    # hodisalari uchun HECH QANDAY blacklist tekshiruvi yo'q edi -
    # faqat dns_query domenlari tekshirilardi. Endi Kerio Connection
    # orqali ma'lum bo'lgan zararli IP/domenga ulanish ham aniqlanadi
    # (masalan qo'lda yoki tashqi threat-intel feed orqali
    # BlacklistEntry'ga qo'shilgan IP/domenlar).
    if event_type == "connection":
        blacklist_hit_found = False
        for target in (parsed.get("dest_ip"), parsed.get("dest_domain")):
            if not target or _is_whitelisted(session, target):
                continue
            bl_hit = _is_blacklisted(session, target)
            if bl_hit:
                alert = Alert(
                    event_id=event.id,
                    device_id=device.id,
                    severity="high",
                    reason=f"Blacklist'dagi manzilga ulanish: {target} (manba: {bl_hit.source})",
                    action_taken="TODO: bloklash backend hali ulanmagan (5-bosqich)",
                    notified=False,
                )
                session.add(alert)
                logger.warning(f"ALERT: {parsed['source_ip']} -> {target} (blacklist, connection)")
                blacklist_hit_found = True
                break

        # ⑦/⑧-band: blacklist'da topilmagan bo'lsa, domen nomi bo'yicha
        # fishing'ga o'xshashligini ham tekshiramiz.
        if not blacklist_hit_found and parsed.get("dest_domain"):
            _check_lexical_phishing_alert(session, event, device, parsed["dest_domain"], parsed["source_ip"])

    raw_log.processed = True


def run_once(session=None):
    own_session = session is None
    session = session or get_session()
    try:
        pending = (
            session.query(RawLog)
            .filter(RawLog.processed == False)  # noqa: E712
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0
        for raw_log in pending:
            process_one(session, raw_log)
        session.commit()
        logger.info(f"{len(pending)} ta yozuv qayta ishlandi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        if own_session:
            session.close()


def run_loop(interval_seconds: int = 5):
    logger.info("Parser engine tsiklda ishga tushdi (Ctrl+C to'xtatish)")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true", help="Doimiy tsiklda ishlash")
    ap.add_argument("--interval", type=int, default=5, help="Tsikl oralig'i (soniya)")
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        count = run_once()
        logger.info(f"Bir martalik ishga tushirish yakunlandi: {count} ta yozuv")
