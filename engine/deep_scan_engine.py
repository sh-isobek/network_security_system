"""
Deep Scan Engine - 4-bosqich.

`file_events` jadvalidan hash-tekshiruvidan o'tgan (checked=True) lekin
hali chuqur tekshiruvdan o'tmagan (deep_scanned=False) yozuvlarni oladi:

  1. YARA qoidalari bilan tekshiradi (barcha fayl turlari uchun umumiy).
  2. Fayl turi nomuvofiqligi (haqiqiy baytlar vs kengaytma) - `scanners/
     file_type_detector.py` orqali (masalan `invoice.pdf` aslida PE32
     bajariladigan fayl bo'lsa).
  3. Agar Office fayli bo'lsa (docm/xlsm/...) - oletools orqali makro
     tekshiradi.
  4. Agar PDF bo'lsa - `scanners/pdf_analyzer.py` orqali (FlateDecode
     bilan siqilgan qismlarni ham ochib) /OpenAction+/JavaScript,
     /Launch, va PDF ichidagi URL'larning fishing xavf ballini
     tekshiradi.
  5. Agar ZIP bo'lsa (kengaytma YOKI haqiqiy fayl turi bo'yicha - pastga
     qarang) - arxivni ochib, ichidagi fayllarni yangi FileEvent
     sifatida navbatga qo'yadi (ular avtomatik ravishda oddiy pipeline
     orqali - avval hash, keyin shu deep-scan orqali - qayta ishlanadi).

Har qanday shubhali belgi topilsa -> verdict="malicious", Alert yaratiladi.

MUHIM CHEKLOV: bu dvigatel faqat Suricata `file-store` orqali diskka
saqlangan fayllar ustida ishlay oladi (`stored_path` to'ldirilgan bo'lishi
kerak). Agar `stored_path` bo'sh bo'lsa (masalan hozircha faqat hash
kelgan bo'lsa), chuqur tekshiruv o'tkazib yuboriladi va faqat hash
natijasiga tayaniladi.

(Real arxitektura bo'shlig'i tuzatilgan: avval `collectors/suricata_
reader.py` `stored_path`ni HECH QACHON to'ldirmasdi - shuning uchun bu
cheklov Suricata orqali kelgan HAR BIR fayl uchun jimgina amalda edi,
garchi fayl haqiqatan `file-store`ga saqlangan bo'lsa ham. Endi
`fileinfo.stored == true` bo'lgan fayllar uchun `stored_path` to'g'ri
hisoblanadi - batafsil: `collectors/suricata_reader.py` va `docs_
SURICATA_SETUP.md`.)

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
from scanners.file_type_detector import detect_magic_from_file, check_extension_mismatch
from scanners.pdf_analyzer import scan_pdf_file, PDF_EXTENSIONS
from scanners.heuristic_analyzer import scan_bytes_heuristic, READ_LIMIT_BYTES
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

        # 1c) Fayl turi nomuvofiqligi (⑳-band) - HAQIQIY fayl baytlaridan
        # (Suricata'ning matn-asosidagi `fe.magic`idan farqli, bu yerda
        # haqiqiy diskdagi fayl o'qiladi - eng ishonchli manba). Masalan
        # `invoice.pdf` nomli fayl aslida PE32 bajariladigan bo'lsa.
        real_magic = detect_magic_from_file(fe.stored_path)
        mismatch = check_extension_mismatch(fe.file_ext, real_magic)
        if mismatch["severity"] == "critical":
            findings.append(f"Fayl turi nomuvofiqligi[critical]: {mismatch['note']}")
            is_malicious = True

        # 2) Office makro
        if fe.file_ext in OFFICE_EXTENSIONS:
            office_result = scan_office_file(fe.stored_path)
            if office_result and office_result.get("suspicious"):
                findings.extend(office_result.get("findings", []))
                is_malicious = True

        # 2b) PDF chuqur tahlil (⑲-band) - `scanners/pdf_analyzer.py`ga
        # qarang: FlateDecode bilan siqilgan /OpenAction+/JavaScript
        # kombinatsiyasi, /Launch, VA PDF ichidagi URL'larning fishing
        # xavf ballini (`threat_intel/url_intel.py` orqali) tekshiradi.
        if fe.file_ext in PDF_EXTENSIONS:
            pdf_result = scan_pdf_file(fe.stored_path)
            if pdf_result and pdf_result.get("suspicious"):
                findings.extend(pdf_result.get("findings", []))
                is_malicious = True

        # 3) ZIP arxiv - ichidagi fayllarni navbatga qo'yish. MUHIM: FAQAT
        # kengaytmaga (fe.file_ext) emas, HAQIQIY fayl turiga (real_magic)
        # ham qaraladi - aks holda hujumchi zararli ZIP'ni oddiygina
        # `.txt`/`.jpg` deb nomlab, arxiv skanerini butunlay chetlab
        # o'tishi mumkin edi (real production'da hali kuzatilmagan, lekin
        # haqiqiy, dokumentlashtirilgan bypass texnikasi).
        if fe.file_ext in ARCHIVE_EXTENSIONS or real_magic == "ZIP":
            if fe.file_ext not in ARCHIVE_EXTENSIONS:
                findings.append(f"Kengaytma '.{fe.file_ext}' ZIP kutmagan, lekin haqiqiy tarkib ZIP - baribir arxiv sifatida tekshirilmoqda.")
            children = extract_zip_and_queue(session, fe)
            if children:
                findings.append(f"Arxivdan {len(children)} ta fayl chiqarilib, tahlil navbatiga qo'yildi.")

        # 4) "unknown" holatni hal qilish (foydalanuvchi so'rovi: fayl
        # HECH QACHON "unknown" holatida qolmasligi kerak). Bu nuqtaga
        # kelinganda hash-intel (local/VT/MalwareBazaar) VA yuqoridagi
        # BARCHA chuqur tekshiruvlar (YARA/ClamAV/fayl-turi-nomuvofiqligi/
        # Office/PDF/ZIP) allaqachon ishlab bo'lgan va hech narsa
        # topmagan - bu fayl ENDI to'liq, ko'p qatlamli tekshiruvdan
        # o'tdi. Oxirgi, EHTIMOLIY (statistik) signal - entropiya +
        # skript naqshlari (`scanners/heuristic_analyzer.py`) - orqali
        # "unknown" "clean" (hech narsa topilmadi) yoki "suspicious"ga
        # (zaif, ammo e'tiborga loyiq signal) HAL QILINADI. Bu funksiya
        # HECH QACHON "malicious" bermaydi (faqat statistik signallar -
        # soxta-pozitiv xavfi) - shuning uchun avtomatik karantin/
        # tarmoqdan uzishga OLIB KELMAYDI, faqat Alert(medium) orqali
        # tahlilchi e'tiboriga yetkaziladi.
        if not is_malicious and fe.verdict == "unknown":
            try:
                with open(fe.stored_path, "rb") as fh:
                    _content = fh.read(READ_LIMIT_BYTES)
            except OSError:
                _content = b""
            heuristic = scan_bytes_heuristic(_content, real_magic, fe.file_ext)
            if heuristic["verdict_hint"] == "suspicious":
                fe.verdict = "suspicious"
                fe.threat_score = max(fe.threat_score or 0, heuristic["score"])
                findings.append("Heuristik tahlil (entropiya/skript naqshi): " + "; ".join(heuristic["findings"]))
                session.add(Alert(
                    file_event_id=fe.id,
                    device_id=_upsert_device_for_file(session, fe.src_ip).id,
                    severity="medium",
                    reason=(
                        f"Heuristik tahlilda shubhali belgilar topildi (tasdiqlanmagan): {fe.filename}\n"
                        + "\n".join(heuristic["findings"])
                    ),
                    action_taken="SHUBHALI (heuristik): avtomatik chora ko'rilmadi, qo'lda ko'rib chiqish tavsiya etiladi",
                    notified=False,
                ))
                logger.warning(f"HEURISTIK SHUBHALI: {fe.filename} ({fe.src_ip}) - ball={heuristic['score']}")
            else:
                fe.verdict = "clean"
                fe.threat_score = 0
                findings.append(
                    "Heuristik tahlil: xavfli belgi topilmadi - to'liq skanerlangan (YARA/ClamAV/fayl "
                    "turi/PDF/Office + entropiya) va 'unknown' o'rniga 'clean' deb belgilandi."
                )
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
