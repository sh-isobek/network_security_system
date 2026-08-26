"""
Markaziy REST API - 6-bosqich.

Windows kompyuterlaridagi Endpoint Agent'lar shu API orqali markaziy
server bilan bog'lanadi:

  POST /api/v1/check_hash        - fayl hash'ini tekshirish (mahalliy
                                    blacklist + agar kerak bo'lsa VT/MB)
  POST /api/v1/report_incident   - agent lokal ravishda fayl bloklagani
                                    haqida markazga xabar berish (Alert
                                    yaratiladi, admin email/Telegram
                                    xabarnomasi shu orqali ishga tushadi)
  GET  /api/v1/health            - agent ishga tushganda serverga
                                    ulanishni tekshirish uchun

MUHIM: Bu API faqat ICHKI tarmoq (172.16.0.0/22) uchun mo'ljallangan,
tashqi internetga ochiq bo'lmasligi SHART. Production'da HTTPS
(o'z-ichki CA sertifikati bilan) va agent autentifikatsiyasi (API key
yoki mTLS) qo'shilishi kerak - bu yerda soddalashtirilgan HTTP+token
namunasi keltirilgan.

Ishga tushirish:
    python -m api.server
"""
import hashlib
import hmac
import os
import sys
from functools import wraps

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import HashBlacklist, Alert, Device, FileEvent, utcnow
from threat_intel.local_checker import check_local
from threat_intel.virustotal_checker import check_virustotal
from threat_intel.malwarebazaar_checker import check_malwarebazaar
from api import token_manager

import logging
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("api_server")

app = Flask(__name__)

# Oddiy shared-secret autentifikatsiya (production'da mTLS/HTTPS bilan almashtirilishi kerak)
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")

        # 1) Eski, umumiy AGENT_API_KEY (orqaga moslik uchun saqlanadi)
        if AGENT_API_KEY and hmac.compare_digest(provided, AGENT_API_KEY):
            return fn(*args, **kwargs)

        # 2) Yangi, alohida kuzatiladigan/bekor qilinadigan API token'lar
        token_info = token_manager.verify_token(provided)
        # Agent tokeni hostname'ga biriktirilgan bo'lsa, boshqa qurilma
        # nomidan ma'lumot yuborishiga yo'l qo'ymaymiz. Qo'lda yaratilgan
        # umumiy integratsiya tokenlarida agent_hostname bo'sh bo'ladi.
        hostname = (request.get_json(silent=True) or {}).get("hostname")
        if token_info is not None and (not token_info.agent_hostname or token_info.agent_hostname == hostname):
            return fn(*args, **kwargs)

        return jsonify({"error": "Ruxsat berilmagan - noto'g'ri API kalit"}), 401
    return wrapper


def require_bootstrap_key(fn):
    """Yangi agent tokeni faqat bootstrap kaliti bilan chiqariladi."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")
        if not AGENT_API_KEY or not hmac.compare_digest(provided, AGENT_API_KEY):
            return jsonify({"error": "Enrollment uchun bootstrap API kaliti kerak"}), 401
        return fn(*args, **kwargs)
    return wrapper


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


def _log_endpoint_scan(session, data: dict, sha256: str, malicious: bool, threat_name: str, source: str):
    """
    Endpoint Agent tomonidan tekshirilgan har bir faylni `file_events`
    jadvaliga yozadi - Dashboard'ning "Fayllar" sahifasida ko'rinishi
    uchun.

    MUHIM: bu yozuv YO'Q edi - agent zararli fayl topmaguncha (Alert
    yaratilmaguncha) Dashboard'da agentning HECH QANDAY faoliyati
    ko'rinmas edi, garchi agent aslida har bir yangi faylni haqiqatan
    tekshirayotgan bo'lsa ham. Bu foydalanuvchida "agent fayllarni
    tekshirmayapti" degan noto'g'ri taassurot qoldirgan. `hostname`/
    `ip_address` yuborilmasa (masalan eski agent versiyasi yoki boshqa
    chaqiruvchi) - jim o'tkazib yuboriladi, tekshiruv natijasiga
    ta'sir qilmaydi.
    """
    hostname = data.get("hostname")
    ip_address = data.get("ip_address")
    if not hostname or not ip_address:
        return

    filename = data.get("filename") or ""
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else None

    entry = FileEvent(
        src_ip=ip_address,
        filename=filename,
        file_ext=file_ext,
        sha256=sha256,
        protocol="endpoint",
        channel="endpoint_agent",
        checked=True,
        verdict="malicious" if malicious else "clean",
        threat_score=100 if malicious else 0,
        checked_sources=source or "endpoint_agent",
    )
    session.add(entry)

    device = session.query(Device).filter(Device.ip_address == ip_address).first()
    if device is not None:
        device.hostname = hostname
        device.last_seen = utcnow()


@app.route("/api/v1/check_hash", methods=["POST"])
@require_api_key
def check_hash():
    """
    So'rov: {"sha256": "...", "filename": "invoice.exe", "hostname": "...", "ip_address": "..."}
    Javob:  {"malicious": bool, "confirmed": bool, "threat_name": str|null, "source": str}

    MUHIM: `confirmed` maydoni - Endpoint Agent avtomatik karantin/
    o'chirishni FAQAT shu maydon `true` bo'lganda amalga oshiradi.
    Bitta VirusTotal antivirus dvigateli signal bergani hali "tasdiqlangan"
    degani emas (soxta-pozitiv xavfi) - shuning uchun VirusTotal uchun
    kamida 3 ta dvigatel VA hisobot beruvchilarning kamida 5% signal
    berishi talab qilinadi. MalwareBazaar (kurallangan zararli dastur
    bazasi) va mahalliy qora ro'yxat esa har doim "tasdiqlangan"
    hisoblanadi (aniq, deterministik moslik).

    `hostname`/`ip_address`/`filename` ixtiyoriy - berilsa, tekshiruv
    Dashboard'ning "Fayllar" sahifasida ko'rish uchun qayd etiladi
    (pastdagi `_log_endpoint_scan` orqali).
    """
    data = request.get_json(silent=True) or {}
    sha256 = (data.get("sha256") or "").lower().strip()

    if not sha256 or len(sha256) != 64:
        return jsonify({"error": "sha256 noto'g'ri yoki bo'sh"}), 400

    session = get_session()
    try:
        local_result = check_local(session, sha256)
        if local_result:
            _log_endpoint_scan(session, data, sha256, True, local_result.get("threat_name"), local_result.get("source") or "local")
            session.commit()
            return jsonify({
                "malicious": True,
                "confirmed": True,
                "threat_name": local_result.get("threat_name"),
                "source": local_result.get("source") or "local",
            })

        # Mahalliyda topilmasa - VirusTotal/MalwareBazaar (server tomonida,
        # shunda agentlar o'zlari internetga chiqmaydi - markazlashtirilgan
        # va tezkorroq, chunki natija darhol keshga tushadi)
        vt = check_virustotal(sha256)
        if vt and vt.get("malicious"):
            positives = int(vt.get("positives") or 0)
            total = int(vt.get("total") or 0)
            confirmed = positives >= 3 and (total == 0 or positives / max(total, 1) >= 0.05)
            if confirmed:
                _add_to_blacklist(session, sha256, vt.get("threat_name"), "virustotal")
            _log_endpoint_scan(session, data, sha256, True, vt.get("threat_name"), "virustotal")
            session.commit()
            return jsonify({
                "malicious": True, "confirmed": confirmed,
                "threat_name": vt.get("threat_name"), "source": "virustotal",
                "positives": positives, "total": total,
            })

        mb = check_malwarebazaar(sha256)
        if mb and mb.get("malicious"):
            _add_to_blacklist(session, sha256, mb.get("threat_name"), "malwarebazaar")
            _log_endpoint_scan(session, data, sha256, True, mb.get("threat_name"), "malwarebazaar")
            session.commit()
            return jsonify({"malicious": True, "confirmed": True, "threat_name": mb.get("threat_name"), "source": "malwarebazaar"})

        _log_endpoint_scan(session, data, sha256, False, None, None)
        session.commit()
        return jsonify({"malicious": False, "confirmed": False, "threat_name": None, "source": None})
    finally:
        session.close()


def _add_to_blacklist(session, sha256: str, threat_name: str, source: str):
    if not session.query(HashBlacklist).filter_by(sha256=sha256).first():
        session.add(HashBlacklist(sha256=sha256, threat_name=threat_name, source=source))
        session.commit()


@app.route("/api/v1/report_incident", methods=["POST"])
@require_api_key
def report_incident():
    """
    Agent lokal ravishda zararli faylni bloklagach, markazga xabar beradi.

    So'rov: {
        "hostname": "ACCOUNTING-PC",
        "ip_address": "172.16.1.45",
        "filename": "invoice.exe",
        "sha256": "...",
        "threat_name": "Trojan.GenericKD",
        "file_deleted": true,
        "process_killed": true,
        "process_name": "outlook.exe",
        "quarantine_path": "C:\\ProgramData\\NetworkSecurityAgent\\Quarantine\\...",
        "quarantined": true
    }
    """
    data = request.get_json(silent=True) or {}

    required = ["hostname", "ip_address", "filename", "sha256"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Majburiy maydonlar yo'q: {missing}"}), 400

    session = get_session()
    try:
        device = session.query(Device).filter(Device.ip_address == data["ip_address"]).first()
        if device is None:
            device = Device(ip_address=data["ip_address"], hostname=data["hostname"], source="endpoint_agent")
            session.add(device)
            session.flush()
        else:
            device.hostname = data["hostname"]

        file_deleted = bool(data.get("file_deleted"))
        process_killed = bool(data.get("process_killed"))
        quarantined = bool(data.get("quarantined"))
        action_parts = []
        if file_deleted:
            action_parts.append("fayl o'chirildi")
        if quarantined:
            action_parts.append("karantinga olindi (" + str(data.get("quarantine_path") or "yo'l noma'lum") + ")")
        if process_killed:
            process_name = data.get("process_name", "nomalum")
            action_parts.append(f"jarayon to'xtatildi ({process_name})")
        action_summary = "Endpoint Agent: " + (", ".join(action_parts) if action_parts else "chora ko'rilmadi")

        threat_name = data.get("threat_name", "nomalum")
        alert = Alert(
            device_id=device.id,
            severity="critical",
            reason=(
                f"Endpoint Agent TASDIQLANGAN zararli faylni aniqladi: {data['filename']} "
                f"[{threat_name}] | Host: {data['hostname']} | SHA256={data['sha256']}"
            ),
            action_taken=action_summary,
            notified=False,
        )
        session.add(alert)
        session.commit()

        logger.warning(f"AGENT INCIDENT: {data['hostname']} ({data['ip_address']}) - {data['filename']} - {action_summary}")
        return jsonify({"status": "recorded", "alert_id": alert.id})
    finally:
        session.close()


@app.route("/api/v1/agent_heartbeat", methods=["POST"])
@require_api_key
def agent_heartbeat():
    """
    Endpoint Agent davriy ravishda (masalan har 5 daqiqada) "men
    tirikman" xabarini yuboradi - bu `network_discovery.agent_coverage`
    modulining "qaysi AD kompyuterda agent hali o'rnatilmagan/to'xtagan"
    hisobotini chiqarishi uchun asosiy manba.

    So'rov: {
        "hostname": "ACCOUNTING-PC",
        "ip_address": "172.16.1.45",
        "agent_version": "1.2.0",
        "agent_os": "windows"
    }
    """
    data = request.get_json(silent=True) or {}

    required = ["hostname", "ip_address"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Majburiy maydonlar yo'q: {missing}"}), 400

    session = get_session()
    try:
        device = session.query(Device).filter(Device.ip_address == data["ip_address"]).first()
        if device is None:
            device = Device(ip_address=data["ip_address"], hostname=data["hostname"], source="endpoint_agent")
            session.add(device)
            session.flush()
        else:
            device.hostname = data["hostname"]

        device.agent_last_heartbeat = utcnow()
        device.agent_version = data.get("agent_version")
        device.agent_os = data.get("agent_os")
        session.commit()

        return jsonify({"status": "ok"})
    finally:
        session.close()


@app.route("/api/v1/agent_enroll", methods=["POST"])
@require_bootstrap_key
def agent_enroll():
    """
    AD/GPO orqali avtomatik joylashtirilayotgan har bir yangi kompyuter
    uchun ALOHIDA, `/api-tokens` sahifasida ko'rinadigan va bekor
    qilinadigan API token chiqaradi.

    So'rov: {"hostname": "ACCOUNTING-PC"}
    Javob:  {"token": "nssk_...", "hostname": "ACCOUNTING-PC"}

    MUHIM: bu endpoint ham `require_api_key` orqali himoyalangan - ya'ni
    chaqiruvchida ALLAQACHON bironta amaldagi kalit (odatda GPO orqali
    SYSVOL'dan tarqatiladigan umumiy "bootstrap" `AGENT_API_KEY`) bo'lishi
    kerak. Natijada olingan token esa SHU KOMPYUTERGA ALOHIDA tegishli -
    Deploy-NetworkSecurityAgent.ps1 buni mahalliy saqlab, keyingi barcha
    so'rovlar uchun umumiy bootstrap kalit o'rniga ishlatadi. Token
    QAYTA KO'RSATILMAYDI - shuning uchun bir xil hostname uchun qayta
    chaqirilsa, oldingi token(lar) avtomatik bekor qilinadi (pastga
    qarang: `token_manager.enroll_agent_token`).
    """
    data = request.get_json(silent=True) or {}
    hostname = (data.get("hostname") or "").strip()
    if not hostname:
        return jsonify({"error": "hostname majburiy"}), 400

    token = token_manager.enroll_agent_token(hostname)
    logger.info(f"AGENT ENROLL: '{hostname}' uchun yangi alohida API token chiqarildi")
    return jsonify({"token": token, "hostname": hostname})


if __name__ == "__main__":
    port = int(os.getenv("API_PORT", "8443"))
    logger.info(f"API server ishga tushmoqda: 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
