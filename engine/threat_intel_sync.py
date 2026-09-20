"""
Threat Intelligence Sync Engine.

URLhaus va ThreatFox (abuse.ch) feed'laridan so'nggi zararli IP/domen/
URL-host'larni olib, `BlacklistEntry` jadvalini avtomatik boyitadi -
hozirgacha bu jadval FAQAT qo'lda to'ldirilardi. Ikkalasi ham mustaqil
(bittasi sozlanmasa, ikkinchisi baribir ishlaydi - UniFi/Ruijie bilan
bir xil naqsh).

MUHIM: bu ATAYLAB faqat "ma'lumot yig'ish" - hech qanday avtomatik
bloklash/javob choralarini o'zi ISHGA TUSHIRMAYDI. `BlacklistEntry`ga
qo'shilgan yozuvlar keyinchalik `engine/parser_engine.py::_is_blacklisted()`
orqali oddiy DNS/connection tekshiruviga kiradi - xuddi qo'lda
qo'shilgan yozuvlar kabi.

Ishga tushirish:
    python -m engine.threat_intel_sync
    python -m engine.threat_intel_sync --loop
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL, THREAT_INTEL_POLL_INTERVAL
from db.database import get_session
from db.models import BlacklistEntry, HashBlacklist, utcnow
from threat_intel.urlhaus_feed import fetch_recent_urls, is_configured as urlhaus_configured
from threat_intel.threatfox_feed import fetch_recent_iocs, fetch_recent_hashes, is_configured as threatfox_configured

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("threat_intel_sync")

# MUHIM (production'da HAQIQATAN topilgan soxta-pozitiv): URLhaus zararli
# faylni umumiy, qonuniy platformada (GitHub, Google Drive, Dropbox...)
# joylashtirilgan URL'larni ham ro'yxatga oladi va `host` sifatida
# "github.com" qaytaradi. Uni domen sifatida blacklist'ga qo'shish esa
# domen ierarxiyasi tekshiruvi (`*.github.com`) tufayli GitHub'ga HAR
# QANDAY ulanishni "high" alertga aylantirdi va response_engine
# xodimning qurilmasini tarmoqdan uzishga urinardi. Host darajasidagi
# blok bu platformalar uchun noto'g'ri - faqat aniq URL/fayl hash'i
# zararli. Bunday host'lar (o'zi va barcha subdomenlari) o'tkazib yuboriladi.
SHARED_PLATFORM_DOMAINS = {
    "github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "bitbucket.org",
    "google.com", "googleapis.com", "googleusercontent.com", "gstatic.com",
    "dropbox.com", "dropboxusercontent.com",
    "onedrive.live.com", "sharepoint.com", "microsoft.com",
    "telegram.org", "t.me", "whatsapp.com", "youtube.com", "facebook.com",
    # Ommaviy CDN/paket registrlari va keng tarqalgan xizmatlar (production'da
    # cdn.jsdelivr.net alertlari 61 marta soxta-pozitiv berdi)
    "jsdelivr.net", "cdnjs.com", "unpkg.com", "npmjs.org", "npmjs.com", "pypi.org",
    "sourceforge.net", "live.com", "office.com", "apple.com", "icloud.com", "mozilla.org",
    "wordpress.com", "blogspot.com", "discord.com", "discordapp.com",
}


def is_shared_platform_host(value: str) -> bool:
    """`value` (domen) SHARED_PLATFORM_DOMAINS'ning o'zi yoki subdomeni bo'lsa True.
    Label chegarasi bo'yicha (oddiy `endswith()` emas - `notgithub.com` mos kelmaydi)."""
    v = (value or "").strip().lower().rstrip(".")
    return any(v == d or v.endswith("." + d) for d in SHARED_PLATFORM_DOMAINS)


def _add_new_entries(session, candidates: list) -> int:
    """
    `candidates` - {"value", "source", "reason"} lug'atlar ro'yxati.
    `BlacklistEntry.value` UNIQUE bo'lgani uchun: (1) mavjud qiymatlarni
    BITTA so'rov bilan oldindan yuklab, (2) partiya ICHIDAGI takrorlarni
    ham chetlab o'tib, faqat HAQIQATAN yangi qiymatlarni qo'shadi.
    """
    if not candidates:
        return 0

    skipped = [c["value"] for c in candidates if is_shared_platform_host(c["value"])]
    if skipped:
        logger.info(f"{len(set(skipped))} ta umumiy platforma host'i o'tkazib yuborildi (masalan {skipped[0]})")
    candidates = [c for c in candidates if not is_shared_platform_host(c["value"])]
    if not candidates:
        return 0

    incoming_values = {c["value"] for c in candidates}
    existing = {
        v for (v,) in session.query(BlacklistEntry.value).filter(BlacklistEntry.value.in_(incoming_values)).all()
    }

    added = 0
    seen_this_batch = set()
    for c in candidates:
        value = c["value"]
        if value in existing or value in seen_this_batch:
            continue
        seen_this_batch.add(value)
        session.add(BlacklistEntry(value=value, source=c["source"], reason=c["reason"], added_at=utcnow()))
        added += 1
    return added


def urlhaus_enabled() -> bool:
    """URLhaus ATAYLAB standart holatda O'CHIQ: feed noto'g'ri (umumiy platformalar,
    qonuniy CDN'lar) ma'lumot berib, soxta-pozitiv alertlarga olib keldi.
    Faqat URLHAUS_ENABLED=true bo'lganda ishlaydi."""
    return os.getenv("URLHAUS_ENABLED", "false").lower() in ("true", "1", "yes")


def sync_urlhaus(session) -> int:
    if not urlhaus_enabled() or not urlhaus_configured():
        return 0
    urls = fetch_recent_urls()
    if urls is None:
        logger.warning("URLhaus so'rovi muvaffaqiyatsiz bo'ldi - bu tsikl o'tkazib yuborildi")
        return 0

    candidates = []
    for item in urls:
        threat = item.get("threat") or "malware_download"
        candidates.append({
            "value": item["host"],
            "source": "urlhaus",
            "reason": f"URLhaus: {threat} ({item.get('url_status', 'unknown')})",
        })
    added = _add_new_entries(session, candidates)
    logger.info(f"URLhaus: {len(urls)} ta yozuv ko'rildi, {added} ta YANGI blacklist yozuvi qo'shildi")
    return added


def sync_threatfox(session) -> int:
    if not threatfox_configured():
        return 0
    iocs = fetch_recent_iocs()
    if iocs is None:
        logger.warning("ThreatFox so'rovi muvaffaqiyatsiz bo'ldi - bu tsikl o'tkazib yuborildi")
        return 0

    candidates = []
    for item in iocs:
        malware = item.get("malware") or "noma'lum"
        candidates.append({
            "value": item["value"],
            "source": "threatfox",
            "reason": f"ThreatFox: {malware} ({item['ioc_type']}, ishonch: {item.get('confidence_level', '?')}%)",
        })
    added = _add_new_entries(session, candidates)
    logger.info(f"ThreatFox: {len(iocs)} ta IOC ko'rildi, {added} ta YANGI blacklist yozuvi qo'shildi")
    return added


def sync_threatfox_hashes(session) -> int:
    """ThreatFox sha256_hash IOC'larini mahalliy HashBlacklist'ga qo'shadi (idempotent)."""
    if not threatfox_configured():
        return 0
    hashes = fetch_recent_hashes()
    if not hashes:
        return 0
    incoming = {h["sha256"] for h in hashes}
    existing = {v for (v,) in session.query(HashBlacklist.sha256).filter(HashBlacklist.sha256.in_(incoming)).all()}
    added, seen = 0, set()
    for h in hashes:
        if h["sha256"] in existing or h["sha256"] in seen:
            continue
        seen.add(h["sha256"])
        session.add(HashBlacklist(sha256=h["sha256"], threat_name=h["malware"], source="threatfox"))
        added += 1
    logger.info(f"ThreatFox: {len(hashes)} ta sha256 IOC ko'rildi, {added} ta YANGI hash_blacklist yozuvi qo'shildi")
    return added


def run_once() -> int:
    if not (urlhaus_enabled() and urlhaus_configured()) and not threatfox_configured():
        return 0

    session = get_session()
    try:
        total = sync_urlhaus(session) + sync_threatfox(session) + sync_threatfox_hashes(session)
        session.commit()
        return total
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = THREAT_INTEL_POLL_INTERVAL):
    logger.info(
        f"Threat Intel sync tsiklda ishga tushdi (URLhaus: {urlhaus_configured()}, "
        f"ThreatFox: {threatfox_configured()}, interval: {interval_seconds}s)"
    )
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=THREAT_INTEL_POLL_INTERVAL)
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        logger.info(f"Yakunlandi: {n} ta yangi blacklist yozuvi qo'shildi")
