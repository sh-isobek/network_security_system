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
import os
import sys
from functools import wraps

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import HashBlacklist, Alert, Device, FileEvent
from threat_intel.local_checker import check_local
from threat_intel.virustotal_checker import check_virustotal
from threat_intel.malwarebazaar_checker import check_malwarebazaar
from api import token_manager

import logging
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("api_server")

app = Flask(__name__)

# Oddiy shared-secret autentifikatsiya (production'da mTLS/HTTPS bilan almashtirilishi kerak)
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "change-me-in-production")


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")

        # 1) Eski, umumiy AGENT_API_KEY (orqaga moslik uchun saqlanadi)
        if provided == AGENT_API_KEY:
            return fn(*args, **kwargs)

        # 2) Yangi, alohida kuzatiladigan/bekor qilinadigan API token'lar
        token_info = token_manager.verify_token(provided)
        if token_info is not None:
            return fn(*args, **kwargs)

        return jsonify({"error": "Ruxsat berilmagan - noto'g'ri API kalit"}), 401
    return wrapper


@app.route("/api/v1/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/v1/check_hash", methods=["POST"])
@require_api_key
def check_hash():
    """
    So'rov: {"sha256": "...", "filename": "invoice.exe"}
    Javob:  {"malicious": bool, "threat_name": str|null, "source": str}
    """
    data = request.get_json(silent=True) or {}
    sha256 = (data.get("sha256") or "").lower().strip()

    if not sha256 or len(sha256) != 64:
        return jsonify({"error": "sha256 noto'g'ri yoki bo'sh"}), 400

    session = get_session()
    try:
        local_result = check_local(session, sha256)
        if local_result:
            return jsonify({
                "malicious": True,
                "threat_name": local_result.get("threat_name"),
                "source": local_result.get("source"),
            })

        # Mahalliyda topilmasa - VirusTotal/MalwareBazaar (server tomonida,
        # shunda agentlar o'zlari internetga chiqmaydi - markazlashtirilgan
        # va tezkorroq, chunki natija darhol keshga tushadi)
        vt = check_virustotal(sha256)
        if vt and vt.get("malicious"):
            _add_to_blacklist(session, sha256, vt.get("threat_name"), "virustotal")
            return jsonify({"malicious": True, "threat_name": vt.get("threat_name"), "source": "virustotal"})

        mb = check_malwarebazaar(sha256)
        if mb and mb.get("malicious"):
            _add_to_blacklist(session, sha256, mb.get("threat_name"), "malwarebazaar")
            return jsonify({"malicious": True, "threat_name": mb.get("threat_name"), "source": "malwarebazaar"})

        return jsonify({"malicious": False, "threat_name": None, "source": None})
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
        "process_name": "outlook.exe"
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
        action_parts = []
        if file_deleted:
            action_parts.append("fayl o'chirildi")
        if process_killed:
            process_name = data.get("process_name", "nomalum")
            action_parts.append(f"jarayon to'xtatildi ({process_name})")
        action_summary = "Endpoint Agent: " + (", ".join(action_parts) if action_parts else "chora ko'rilmadi")

        threat_name = data.get("threat_name", "nomalum")
        alert = Alert(
            device_id=device.id,
            severity="critical",
            reason=(
                f"Endpoint Agent zararli faylni aniqladi: {data['filename']} "
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


if __name__ == "__main__":
    port = int(os.getenv("API_PORT", "8443"))
    logger.info(f"API server ishga tushmoqda: 0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port)
