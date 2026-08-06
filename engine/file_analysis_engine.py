"""
File Analysis Engine - 3-bosqich.

Vazifasi:
  `file_events` jadvalidan checked=False bo'lgan yozuvlarni oladi va
  hash'ni ketma-ket manbalar orqali tekshiradi:

      1. Mahalliy blacklist (tezkor, cheklovsiz)
      2. VirusTotal (agar API kalit sozlangan bo'lsa)
      3. MalwareBazaar (bepul, API kalitsiz)

  Birinchi "malicious" javob topilishi bilan tekshiruv to'xtaydi va
  natija darhol hash_blacklist jadvaliga qo'shiladi - shu hash boshqa
  fayl orqali qayta kelsa, endi tarmoqqa chiqmasdan darhol aniqlanadi.

  Zararli topilsa -> Alert yaratiladi (Threat Score = 100), action_taken
  ustuniga "5-bosqichda ulanadigan" bloklash choralari yoziladi (hozircha
  TODO, chunki bloklash backend hali tanlanmagan).

Ishga tushirish:
    python -m engine.file_analysis_engine --once
    python -m engine.file_analysis_engine --loop
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import FileEvent, Alert, HashBlacklist, Device
from threat_intel.local_checker import check_local
from threat_intel.virustotal_checker import check_virustotal
from threat_intel.malwarebazaar_checker import check_malwarebazaar

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("file_analysis_engine")

BATCH_SIZE = 50

# Zararli deb topilgan file turlariga qarab og'irlik darajasi (loglash/xabarnoma uchun)
HIGH_RISK_EXTENSIONS = {"exe", "dll", "msi", "js", "vbs", "ps1", "docm", "xlsm", "apk"}


def _add_to_local_blacklist(session, sha256: str, threat_name: str, source: str):
    if not session.query(HashBlacklist).filter_by(sha256=sha256).first():
        session.add(HashBlacklist(sha256=sha256, threat_name=threat_name, source=source))


def _upsert_device_for_file(session, ip: str) -> "Device":
    device = session.query(Device).filter(Device.ip_address == ip).first()
    if device is None:
        device = Device(ip_address=ip, source="suricata_fileinfo")
        session.add(device)
        session.flush()
    return device


def analyze_one(session, fe: FileEvent):
    sources_checked = []

    # 1) Mahalliy blacklist
    result = check_local(session, fe.sha256)
    sources_checked.append("local")

    # 2) VirusTotal (agar mahalliyda topilmasa)
    if result is None:
        vt_result = check_virustotal(fe.sha256)
        sources_checked.append("virustotal")
        if vt_result and vt_result.get("malicious"):
            result = {"malicious": True, "threat_name": vt_result.get("threat_name") or "Malicious (VirusTotal)"}

    # 3) MalwareBazaar (agar hali topilmasa)
    if result is None:
        mb_result = check_malwarebazaar(fe.sha256)
        sources_checked.append("malwarebazaar")
        if mb_result and mb_result.get("malicious"):
            result = {"malicious": True, "threat_name": mb_result.get("threat_name") or "Malicious (MalwareBazaar)"}

    fe.checked = True
    fe.checked_sources = ",".join(sources_checked)

    if result and result.get("malicious"):
        fe.verdict = "malicious"
        fe.threat_score = 100
        _add_to_local_blacklist(session, fe.sha256, result.get("threat_name"), source="auto")

        risk_note = " (yuqori xavfli fayl turi)" if fe.file_ext in HIGH_RISK_EXTENSIONS else ""
        device = _upsert_device_for_file(session, fe.src_ip)
        alert = Alert(
            file_event_id=fe.id,
            device_id=device.id,
            severity="critical",
            reason=(
                f"Zararli fayl aniqlandi: {fe.filename} "
                f"[{result.get('threat_name')}]{risk_note} | SHA256={fe.sha256}"
            ),
            action_taken="TODO: karantin/bloklash backend hali ulanmagan (5-bosqich)",
            notified=False,
        )
        session.add(alert)
        logger.warning(f"ZARARLI FAYL: {fe.filename} ({fe.src_ip} -> {fe.dest_ip}) - {result.get('threat_name')}")
    else:
        fe.verdict = "clean"
        fe.threat_score = 0


def run_once():
    session = get_session()
    try:
        pending = (
            session.query(FileEvent)
            .filter(FileEvent.checked == False)  # noqa: E712
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0
        for fe in pending:
            analyze_one(session, fe)
        session.commit()
        logger.info(f"{len(pending)} ta fayl tekshirildi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = 10):
    logger.info("File analysis engine tsiklda ishga tushdi")
    while True:
        try:
            run_once()
        except Exception as exc:
            logger.error(f"Tsikl xatoligi: {exc}")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--loop", action="store_true")
    ap.add_argument("--interval", type=int, default=10)
    args = ap.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once()
        logger.info(f"Yakunlandi: {n} ta fayl tekshirildi")
