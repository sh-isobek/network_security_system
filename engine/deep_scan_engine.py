"""
Deep Scan Engine - 4-bosqich.

`file_events` jadvalidan hash-tekshiruvidan o'tgan (checked=True) lekin
hali chuqur tekshiruvdan o'tmagan (deep_scanned=False) yozuvlarni oladi:

  1. YARA qoidalari bilan tekshiradi (barcha fayl turlari uchun umumiy).
  2. Agar Office fayli bo'lsa (docm/xlsm/...) - oletools orqali makro
     tekshiradi.
  3. Agar ZIP bo'lsa - arxivni ochib, ichidagi fayllarni yangi FileEvent
     sifatida navbatga qo'yadi (ular avtomatik ravishda oddiy pipeline
     orqali - avval hash, keyin shu deep-scan orqali - qayta ishlanadi).

Har qanday shubhali belgi topilsa -> verdict="malicious", Alert yaratiladi.

MUHIM CHEKLOV: bu dvigatel faqat Suricata `file-store` orqali diskka
saqlangan fayllar ustida ishlay oladi (`stored_path` to'ldirilgan bo'lishi
kerak). Agar `stored_path` bo'sh bo'lsa (masalan hozircha faqat hash
kelgan bo'lsa), chuqur tekshiruv o'tkazib yuboriladi va faqat hash
natijasiga tayaniladi.

Ishga tushirish:
    python -m engine.deep_scan_engine
    python -m engine.deep_scan_engine --loop
"""
import argparse
import logging
import os
import sys
import time

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import FileEvent, Alert, Device
from scanners.yara_scanner import scan_file as yara_scan_file
from scanners.office_scanner import scan_office_file, OFFICE_EXTENSIONS
from scanners.archive_scanner import extract_zip_and_queue
from scanners.clamav_scanner import scan_file as clamav_scan_file, is_database_available as clamav_db_available
from engine.quarantine import quarantine_file

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("deep_scan_engine")

BATCH_SIZE = 50
ARCHIVE_EXTENSIONS = {"zip"}  # RAR - docs_SURICATA_SETUP.md'da izoh berilgan, alohida kengaytiriladi


def _upsert_device_for_file(session, ip: str) -> Device:
    device = session.query(Device).filter(Device.ip_address == ip).first()
    if device is None:
        device = Device(ip_address=ip, source="suricata_fileinfo")
        session.add(device)
        session.flush()
    return device


def deep_scan_one(session, fe: FileEvent):
    findings = []
    is_malicious = False

    # 1) YARA
    if fe.stored_path and os.path.isfile(fe.stored_path):
        yara_hits = yara_scan_file(fe.stored_path)
        for hit in yara_hits:
            findings.append(f"YARA[{hit['severity']}]: {hit['rule']} - {hit['description']}")
            if hit["severity"] in ("high", "critical"):
                is_malicious = True

        # 1b) ClamAV - imzo-asosli antivirus (YARA'ga qo'shimcha qatlam)
        clamav_result = clamav_scan_file(fe.stored_path)
        if clamav_result.get("error"):
            findings.append(f"ClamAV: tekshirib bo'lmadi ({clamav_result['error']})")
        elif clamav_result.get("infected"):
            findings.append(f"ClamAV[critical]: {clamav_result['signature']}")
            is_malicious = True

        # 2) Office makro
        if fe.file_ext in OFFICE_EXTENSIONS:
            office_result = scan_office_file(fe.stored_path)
            if office_result and office_result.get("suspicious"):
                findings.extend(office_result.get("findings", []))
                is_malicious = True

        # 3) ZIP arxiv - ichidagi fayllarni navbatga qo'yish
        if fe.file_ext in ARCHIVE_EXTENSIONS:
            children = extract_zip_and_queue(session, fe)
            if children:
                findings.append(f"Arxivdan {len(children)} ta fayl chiqarilib, tahlil navbatiga qo'yildi.")
    else:
        findings.append("stored_path mavjud emas - chuqur tekshiruv o'tkazib yuborildi (faqat hash natijasi asosida).")

    fe.deep_scanned = True
    fe.deep_scan_findings = "\n".join(findings) if findings else None

    if is_malicious and fe.verdict != "malicious":
        fe.verdict = "malicious"
        fe.threat_score = 100

        # MUHIM: chuqur tekshiruv (YARA qoidasi/ClamAV imzosi) - VirusTotal'ning
        # ehtimoliy ko'p-dvigatel ovoz berishidan farqli - aniq, deterministik
        # pattern moslashuvi. Shuning uchun bu yerda topilgan zararli fayl
        # to'g'ridan-to'g'ri (server tomonidagi, `stored_path` mavjud bo'lsa)
        # xavfsiz karantinga olinadi.
        quarantine_result = {"quarantined": False, "quarantine_path": None, "source_removed": False, "error": "stored_path mavjud emas"}
        if fe.stored_path and os.path.isfile(fe.stored_path):
            quarantine_result = quarantine_file(fe.stored_path, fe.sha256, "Deep scan: " + "; ".join(findings)[:500])
            findings.append("Karantin: " + (quarantine_result.get("quarantine_path") or quarantine_result.get("error", "muvaffaqiyatsiz")))
        action = "Tasdiqlangan malware: karantinaga olindi" if quarantine_result.get("quarantined") else "Tasdiqlangan malware: karantinaga olish muvaffaqiyatsiz"

        alert = Alert(
            file_event_id=fe.id,
            device_id=_upsert_device_for_file(session, fe.src_ip).id,
            severity="critical",
            reason=f"Chuqur tekshiruvda shubhali belgilar topildi: {fe.filename}\n" + "\n".join(findings),
            action_taken=action,
            notified=False,
        )
        session.add(alert)
        logger.warning(f"DEEP-SCAN ALERT: {fe.filename} ({fe.src_ip}) - {len(findings)} ta topilma")


def run_once():
    session = get_session()
    try:
        pending = (
            session.query(FileEvent)
            .filter(FileEvent.checked == True, FileEvent.deep_scanned == False)  # noqa: E712
            .limit(BATCH_SIZE)
            .all()
        )
        if not pending:
            return 0
        for fe in pending:
            deep_scan_one(session, fe)
        session.commit()
        logger.info(f"{len(pending)} ta fayl chuqur tekshirildi")
        return len(pending)
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def run_loop(interval_seconds: int = 10):
    logger.info("Deep scan engine tsiklda ishga tushdi")
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
        logger.info(f"Yakunlandi: {n} ta fayl chuqur tekshirildi")
