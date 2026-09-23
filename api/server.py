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
import json
import re
from urllib.parse import unquote
from functools import wraps

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from flask_limiter import Limiter

from config.settings import LOG_LEVEL
from db.database import get_session
from db.models import HashBlacklist, Alert, Device, FileEvent, FileDecision, utcnow
from threat_intel.local_checker import check_local
from threat_intel.virustotal_checker import check_virustotal, vt_slot_busy
from threat_intel.malwarebazaar_checker import check_malwarebazaar
from scanners.heuristic_analyzer import SUSPICIOUS_SCORE_THRESHOLD
from api import token_manager
from scanners.upload_scanner import scan_upload, MAX_UPLOAD_BYTES

import logging
logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("api_server")

# VT 'tasdiqlangan' chegarasi: mashhur qonuniy dasturlar (WinRAR/AnyDesk/...) ham 3-5 dvigatelda PUA/riskware
# sifatida belgilanadi - avtomatik o'chirish uchun ancha yuqori ishonch kerak.
VT_CONFIRM_MIN_ENGINES = int(os.getenv("VT_CONFIRM_MIN_ENGINES", "10"))
VT_CONFIRM_MIN_RATIO = float(os.getenv("VT_CONFIRM_MIN_RATIO", "0.15"))

app = Flask(__name__)
app.config["UPLOAD_SCAN_ROOT"] = os.getenv("UPLOAD_SCAN_ROOT", "/tmp/endpoint-scans")
app.config["UPLOAD_SCAN_MAX_BYTES"] = MAX_UPLOAD_BYTES

# Oddiy shared-secret autentifikatsiya (production'da mTLS/HTTPS bilan almashtirilishi kerak)
#
# XAVFSIZLIK (CRITICAL, tuzatilgan): bu yerda ilgari `os.getenv("AGENT_API_KEY",
# "change-me-in-production")` bor edi - agar administrator .env faylida
# AGENT_API_KEY'ni sozlashni unutsa, server SHU ANIQ, OMMAVIY MA'LUM
# (GitHub'dagi ochiq manba kodida ko'rinadigan) qatorni "to'g'ri kalit"
# sifatida qabul qilardi - istalgan kishi shu standart qiymatni yuborib,
# himoyalanmagan production serverga to'liq kirishi mumkin edi.
#
# Endi standart qiymat YO'Q. Agar AGENT_API_KEY bo'sh bo'lsa, eski umumiy-
# kalit autentifikatsiya yo'li BUTUNLAY O'CHIRILADI (pastda `if AGENT_API_KEY
# and ...`) - faqat per-agent, bekor qilinadigan token'lar (`api/token_
# manager.py`, /api-tokens Dashboard sahifasi) orqali kirish qoladi. Bu
# "yopiq holatda muvaffaqiyatsiz bo'lish" (fail-closed) - noto'g'ri
# sozlangan server hech kimni HAM kiritmaydi, noto'g'ri kishini emas.
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")
if not AGENT_API_KEY:
    logger.warning(
        "AGENT_API_KEY sozlanmagan - eski umumiy-kalit autentifikatsiyasi "
        "O'CHIRILGAN (faqat per-agent token'lar orqali kirish mumkin). "
        "Eski Agent'lar bilan orqaga moslik kerak bo'lsa, .env faylida "
        "AGENT_API_KEY'ga kuchli, tasodifiy qiymat bering."
    )


# --- Rate limiting (XAVFSIZLIK: agent API'ga hech qanday so'rov chegarasi
# yo'q edi - bitta buzilgan/zararli agent yoki tokenni o'g'irlagan
# hujumchi cheksiz `check_hash` so'rovi yuborib, serverni va tashqi
# VirusTotal/MalwareBazaar API kvotasini ishdan chiqarishi mumkin edi). ---
def _rate_limit_key() -> str:
    """
    Har bir agent/token uchun ALOHIDA chegara (bitta buzilgan agent
    boshqalarni bloklab qo'ymasin) - autentifikatsiya kaliti mavjud
    bo'lsa shundan (xeshlab, log/xotirada ochiq saqlanmasin), aks holda
    so'rov IP manzilidan foydalaniladi.
    """
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return "ip:" + (request.remote_addr or "unknown")


limiter = Limiter(
    key_func=_rate_limit_key,
    app=app,
    default_limits=[os.getenv("API_RATE_LIMIT_GLOBAL", "1000 per minute")],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,
)


# --- Rate limiting (XAVFSIZLIK: agent API'ga hech qanday so'rov chegarasi
# yo'q edi - bitta buzilgan/zararli agent yoki tokenni o'g'irlagan
# hujumchi cheksiz `check_hash` so'rovi yuborib, serverni va tashqi
# VirusTotal/MalwareBazaar API kvotasini ishdan chiqarishi mumkin edi). ---
def _rate_limit_key() -> str:
    """
    Har bir agent/token uchun ALOHIDA chegara (bitta buzilgan agent
    boshqalarni bloklab qo'ymasin) - autentifikatsiya kaliti mavjud
    bo'lsa shundan (xeshlab, log/xotirada ochiq saqlanmasin), aks holda
    so'rov IP manzilidan foydalaniladi.
    """
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        return "key:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]
    return "ip:" + (request.remote_addr or "unknown")


limiter = Limiter(
    key_func=_rate_limit_key,
    app=app,
    default_limits=[os.getenv("API_RATE_LIMIT_GLOBAL", "1000 per minute")],
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    headers_enabled=True,
)


def require_api_key(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        provided = request.headers.get("X-API-Key", "")

        # 1) Eski, umumiy AGENT_API_KEY (orqaga moslik uchun saqlanadi, LEKIN
        # faqat AGENT_API_KEY haqiqatan sozlangan bo'lsagina tekshiriladi -
        # bo'sh/sozlanmagan holatda bu yo'l butunlay o'chiq, `provided`
        # bo'sh qatorga TENGLASHIB "muvaffaqiyatli" bo'lib qolmasligi kerak.
        # `hmac.compare_digest` - vaqt-asosli (timing) hujumlardan himoya
        # uchun oddiy `==` o'rniga).
        if AGENT_API_KEY and hmac.compare_digest(provided, AGENT_API_KEY):
            return fn(*args, **kwargs)

        # 2) Yangi, alohida kuzatiladigan/bekor qilinadigan API token'lar
        token_info = token_manager.verify_token(provided)
        # Agent tokeni hostname'ga biriktirilgan bo'lsa, boshqa qurilma
        # nomidan ma'lumot yuborishiga yo'l qo'ymaymiz. Qo'lda yaratilgan
        # umumiy integratsiya tokenlarida agent_hostname bo'sh bo'ladi.
        hostname = (request.headers.get("X-Agent-Hostname") if request.endpoint == "scan_file_upload"
                    else (request.get_json(silent=True) or {}).get("hostname"))
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
@limiter.exempt
def health():
    return jsonify({"status": "ok"})


@app.route("/api/v1/scan_file", methods=["POST"])
@limiter.limit("6 per minute")
@require_api_key
def scan_file_upload():
    """Raw file bytes, authenticated before reading. No persistent sample copy."""
    limit = app.config["UPLOAD_SCAN_MAX_BYTES"]
    if request.mimetype != "application/octet-stream":
        return jsonify({"error": "application/octet-stream required"}), 415
    if request.content_length is None:
        return jsonify({"error": "Content-Length required"}), 411
    if request.content_length > limit:
        return jsonify({"error": "File too large"}), 413
    filename = unquote(request.headers.get("X-File-Name", "sample.bin"))
    if len(filename) > 255:
        return jsonify({"error": "Filename too long"}), 400
    result = scan_upload(
        request.stream, request.headers.get("X-File-SHA256", "").lower(),
        filename, app.config["UPLOAD_SCAN_ROOT"], limit,
    )
    # Sample has already been deleted. Only hash and analysis survive in DB.
    session = get_session()
    try:
        session.add(FileEvent(
            src_ip=request.remote_addr or "unknown",
            sha256=result["sha256"], protocol="endpoint", channel="endpoint_upload",
            checked=True, deep_scanned=True, verdict=result["verdict"],
            threat_score=result["score"], checked_sources=result["source"],
            deep_scan_findings=json.dumps({
                "findings": result["findings"],
                "scan_complete": result["scan_complete"],
                "scan_warning": result.get("scan_warning"),
            }, ensure_ascii=False),
        ))
        session.commit()
    finally:
        session.close()
    return jsonify(result)


def _extract_username_from_path(filepath):
    """
    Qurilmadagi to'liq fayl yo'lidan (masalan "C:\\Users\\d.turgunbaev-su\\Downloads\\x.exe")
    foydalanuvchi login nomini ajratib oladi - Alert matnida "IP=127.0.0.1" kabi holatlarda ham
    QAYSI foydalanuvchi ekanligini ko'rsatish uchun (Windows/macOS "Users", Linux "home").
    Yo'l yo'q yoki naqshga mos kelmasa - None.
    """
    if not filepath:
        return None
    m = re.search(r"[\\/][Uu]sers[\\/]([^\\/]+)[\\/]", filepath)
    if m:
        return m.group(1)
    m = re.search(r"/home/([^/]+)/", filepath)
    if m:
        return m.group(1)
    return None


def _log_endpoint_scan(session, data: dict, sha256: str, verdict: str, threat_score: int,
                        threat_name: str, source: str):
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

    `verdict` chaqiruvchi (`check_hash()`) tomonidan hisoblab
    beriladi - "malicious"/"suspicious"/"clean"/"unknown" (`engine/
    file_analysis_engine.py::analyze_one()`dagi bir xil taksonomiya -
    "hech qanday manba ma'lumot bermadi" endi "clean" bilan
    aralashtirilmaydi).
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
        device_file_path=data.get("filepath") or None,
        sha256=sha256,
        protocol="endpoint",
        channel="endpoint_agent",
        checked=True,
        verdict=verdict,
        threat_score=threat_score,
        checked_sources=source or "endpoint_agent",
    )
    session.add(entry)

    device = session.query(Device).filter(Device.ip_address == ip_address).first()
    if device is not None:
        device.hostname = hostname
        device.last_seen = utcnow()


@app.route("/api/v1/check_hash", methods=["POST"])
@limiter.limit(os.getenv("API_RATE_LIMIT_CHECK_HASH", "240 per minute"))
@require_api_key
def check_hash():
    """
    So'rov: {"sha256": "...", "filename": "invoice.exe", "filepath": "C:\\Users\\jsmith\\Downloads\\invoice.exe",
             "hostname": "...", "ip_address": "...", "magic": "PE"|null,
             "heuristic_score": 0-100, "heuristic_findings": [str],
             "heuristic_verdict": "malicious"|"suspicious"|"clean"|null}
    Javob:  {"malicious": bool, "confirmed": bool, "threat_name": str|null, "source": str}

    `magic`/`heuristic_*` - ixtiyoriy, `agent_core/agent.py::analyze_file()`
    tomonidan hisoblangan MAHALLIY (fayl mazmuni FAQAT endpoint'da
    mavjud - server hech qachon fayl baytlarini olmaydi) statik tahlil
    natijasi. Foydalanuvchi so'rovi: "unknown" fayl hech qachon
    qolmasin - pastga qarang.

    MUHIM: `confirmed` maydoni - Endpoint Agent avtomatik karantin/
    o'chirishni FAQAT shu maydon `true` bo'lganda amalga oshiradi.
    Bitta VirusTotal antivirus dvigateli signal bergani hali "tasdiqlangan"
    degani emas (soxta-pozitiv xavfi) - shuning uchun VirusTotal uchun
    kamida 3 ta dvigatel VA hisobot beruvchilarning kamida 5% signal
    berishi talab qilinadi. MalwareBazaar (kurallangan zararli dastur
    bazasi) va mahalliy qora ro'yxat esa har doim "tasdiqlangan"
    hisoblanadi (aniq, deterministik moslik).

    MUHIM (real production xatosi tuzatilgan - Agent'ga yuboriladigan
    javob emas, `file_events`ga yoziladigan yozuv): "hech qanday manba
    bu hash haqida ma'lumot bermadi" (masalan yangi, hali VT/
    MalwareBazaar bazasida bo'lmagan fayl) avval `verdict="clean"`
    sifatida yozilardi. Endi bu holat `verdict="unknown"` sifatida
    qayd etiladi (Agent'ga qaytariladigan `malicious`/`confirmed`
    JSON javobi - ya'ni Agent'ning karantin qarori - O'ZGARMAYDI: har
    ikkala holatda ham `malicious=False`, chunki noma'lum faylni
    avtomatik o'chirish o'zi boshqa, alohida xavf - ko'pchilik
    noma'lum fayl aslida zararsiz. Bu faqat Dashboard'dagi "Fayllar"
    yozuvi qanday YORLIQLANISHIGA tegishli - tahlilchi endi "bu fayl
    haqiqatan tekshirilib toza topilgan" bilan "bu fayl haqida
    umuman ma'lumot yo'q"ni farqlay oladi).

    `hostname`/`ip_address`/`filename`/`filepath` ixtiyoriy - berilsa, tekshiruv
    Dashboard'ning "Fayllar" sahifasida ko'rish uchun qayd etiladi
    (pastdagi `_log_endpoint_scan` orqali).
    """
    data = request.get_json(silent=True) or {}
    sha256 = (data.get("sha256") or "").lower().strip()

    if not sha256 or len(sha256) != 64:
        return jsonify({"error": "sha256 noto'g'ri yoki bo'sh"}), 400

    session = get_session()
    try:
        # ADMIN QARORI (SHA256 bo'yicha, barcha qurilmalar uchun) - eng yuqori ustuvorlik.
        decision = session.query(FileDecision).filter_by(sha256=sha256).first()
        if decision is not None and decision.decision == "safe":
            _log_endpoint_scan(session, data, sha256, "clean", 0, None, "admin_decision")
            session.commit()
            return jsonify({"malicious": False, "confirmed": False, "threat_name": None,
                            "source": "admin_decision", "admin_decision": "safe"})
        if decision is not None and decision.decision == "malicious":
            _log_endpoint_scan(session, data, sha256, "malicious", 100, decision.note or "Admin: zararli", "admin_decision")
            session.commit()
            return jsonify({"malicious": True, "confirmed": True, "threat_name": decision.note or "Admin qarori: zararli",
                            "source": "admin_decision", "admin_decision": "malicious", "admin_action": "quarantine"})

        local_result = check_local(session, sha256)
        if local_result:
            _log_endpoint_scan(session, data, sha256, "malicious", 100,
                                local_result.get("threat_name"), local_result.get("source") or "local")
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
        vt_deferred = vt_slot_busy()
        vt = None if vt_deferred else check_virustotal(sha256)
        if vt is not None and vt.get("malicious"):
            positives = int(vt.get("positives") or 0)
            total = int(vt.get("total") or 0)
            confirmed = positives >= VT_CONFIRM_MIN_ENGINES and (total == 0 or positives / max(total, 1) >= VT_CONFIRM_MIN_RATIO)
            if confirmed:
                _add_to_blacklist(session, sha256, vt.get("threat_name"), "virustotal")
            _log_endpoint_scan(session, data, sha256, "malicious" if confirmed else "suspicious",
                                100 if confirmed else 60, vt.get("threat_name"), "virustotal")
            session.commit()
            return jsonify({
                "malicious": True, "confirmed": confirmed,
                "threat_name": vt.get("threat_name"), "source": "virustotal",
                "positives": positives, "total": total,
                "upload_required": not confirmed,
            })

        # VT hashni HAQIQATAN tekshirdi (None emas) va hech qaysi dvigatel
        # belgilamadi - bu haqiqiy "toza" signali (404/ma'lumot yo'q holati
        # `check_virustotal()`da allaqachon `None` bilan ajratilgan).
        vt_scanned_clean = vt is not None and not vt.get("malicious")

        mb = check_malwarebazaar(sha256)
        if mb and mb.get("malicious"):
            _add_to_blacklist(session, sha256, mb.get("threat_name"), "malwarebazaar")
            _log_endpoint_scan(session, data, sha256, "malicious", 100, mb.get("threat_name"), "malwarebazaar")
            session.commit()
            return jsonify({"malicious": True, "confirmed": True, "threat_name": mb.get("threat_name"), "source": "malwarebazaar"})

        # MUHIM (foydalanuvchi so'rovi - "unknown" fayl hech qachon
        # qolmasin): hash-intel (local/VT/MalwareBazaar) hech narsa
        # DEMAGANDA (vt_scanned_clean=False bo'lsa - VT haqiqatan
        # "toza" deb TASDIQLAGAN holatda heuristik e'tiborsiz
        # qoldiriladi, bu tasdiqni ustidan yozmaslik uchun), Agent
        # o'zi hisoblagan HEURISTIK signal (fayl mazmuni FAQAT
        # endpoint'da mavjud - server hech qachon fayl baytlarini
        # olmaydi, `scanners/heuristic_analyzer.py`) bilan yakuniy
        # "unknown" hal qilinadi. Bu Agent'ga qaytariladigan
        # `malicious`/`confirmed`ga HECH QANDAY ta'sir qilmaydi
        # (Agent o'z avtomatik karantin qarorini mahalliy ravishda,
        # MUSTAQIL hisoblaydi - `agent_core/agent.py::_on_new_file()`)
        # - bu yerda FAQAT Dashboard'dagi "Fayllar" yorlig'i va Alert
        # tahlilchi ko'rishi uchun.
        heuristic_verdict = data.get("heuristic_verdict")
        heuristic_score = int(data.get("heuristic_score") or 0)
        heuristic_findings = data.get("heuristic_findings") or []

        if not vt_scanned_clean and heuristic_verdict in ("malicious", "suspicious"):
            severity = "critical" if heuristic_verdict == "malicious" else "medium"
            log_verdict = "malicious" if heuristic_verdict == "malicious" else "suspicious"
            threat_score = 100 if heuristic_verdict == "malicious" else min(max(heuristic_score, SUSPICIOUS_SCORE_THRESHOLD), 95)
            _log_endpoint_scan(session, data, sha256, log_verdict, threat_score, None, "heuristic")
            device = session.query(Device).filter(Device.ip_address == data.get("ip_address")).first()
            if device is not None and data.get("filename"):
                _fp = data.get("filepath")
                _user = _extract_username_from_path(_fp)
                _path_note = f" | Yo'l: {_fp}" if _fp else ""
                _user_note = f" | Foydalanuvchi: {_user}" if _user else ""
                session.add(Alert(
                    device_id=device.id,
                    severity=severity,
                    reason=(
                        f"Endpoint heuristik tahlilida {'tasdiqlangan' if heuristic_verdict == 'malicious' else 'shubhali'} "
                        f"fayl: {data.get('filename')} | Host: {data.get('hostname')}{_user_note} | SHA256={sha256}{_path_note}\n"
                        + "\n".join(heuristic_findings)
                    ),
                    action_taken=(
                        "Mahalliy heuristik orqali tasdiqlangan (endpoint'da alohida ko'rib chiqilgan)"
                        if heuristic_verdict == "malicious"
                        else "SHUBHALI (heuristik): avtomatik chora ko'rilmadi, qo'lda ko'rib chiqish tavsiya etiladi"
                    ),
                    notified=False,
                ))
            session.commit()
            return jsonify({"malicious": False, "confirmed": False, "threat_name": None, "source": None,
                            "upload_required": True})

        final_verdict = "clean" if vt_scanned_clean else "unknown"
        _log_endpoint_scan(session, data, sha256, final_verdict, 0, None, None)
        if vt_deferred and final_verdict == "unknown":
            # VT slot band edi (bepul tarif) - fon `file_analysis_engine` o'z sur'ati bilan tekshiradi
            session.flush()
            _fe = (session.query(FileEvent).filter(FileEvent.sha256 == sha256, FileEvent.channel == "endpoint_agent")
                   .order_by(FileEvent.id.desc()).first())
            if _fe is not None:
                _fe.checked = False
        session.commit()
        return jsonify({"malicious": False, "confirmed": False, "threat_name": None, "source": None,
                        "upload_required": not vt_scanned_clean or heuristic_verdict in ("suspicious", "malicious")})
    finally:
        session.close()


def _add_to_blacklist(session, sha256: str, threat_name: str, source: str):
    if not session.query(HashBlacklist).filter_by(sha256=sha256).first():
        session.add(HashBlacklist(sha256=sha256, threat_name=threat_name, source=source))
        session.commit()


@app.route("/api/v1/report_incident", methods=["POST"])
@limiter.limit(os.getenv("API_RATE_LIMIT_REPORT_INCIDENT", "10 per minute"))
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
        filepath = data.get("filepath")
        path_note = f" | Yo'l: {filepath}" if filepath else ""
        username = _extract_username_from_path(filepath)
        user_note = f" | Foydalanuvchi: {username}" if username else ""
        awaiting = bool(data.get("awaiting_admin"))
        fe_link = (session.query(FileEvent.id).filter(FileEvent.sha256 == data["sha256"], FileEvent.channel == "endpoint_agent")
                   .order_by(FileEvent.id.desc()).first())
        if awaiting:
            # Fayl O'CHIRILMAGAN - admin qarorini kutadi. Bir xil (qurilma, hash) uchun takroriy alert yo'q.
            dup = session.query(Alert.id).filter(Alert.device_id == device.id, Alert.reason.like(f"%SHA256={data['sha256']}%")).first()
            if dup is not None:
                return jsonify({"status": "duplicate", "alert_id": dup[0]})
            alert = Alert(
                device_id=device.id, severity="high", file_event_id=fe_link[0] if fe_link else None,
                reason=(f"Endpoint Agent zararli deb GUMON QILGAN fayl: {data['filename']} "
                        f"[{threat_name}] | Host: {data['hostname']}{user_note} | SHA256={data['sha256']}{path_note}"),
                action_taken="Fayl tegilmadi - ADMIN QARORI kutilmoqda (Zararsiz / Zararli tugmalari)",
                notified=False,
            )
        else:
            alert = Alert(
                device_id=device.id,
                severity="critical", file_event_id=fe_link[0] if fe_link else None,
                reason=(
                    f"Endpoint Agent TASDIQLANGAN zararli faylni aniqladi: {data['filename']} "
                    f"[{threat_name}] | Host: {data['hostname']}{user_note} | SHA256={data['sha256']}{path_note}"
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
@limiter.limit(os.getenv("API_RATE_LIMIT_HEARTBEAT", "12 per minute"))
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
@limiter.limit(os.getenv("API_RATE_LIMIT_ENROLL", "30 per minute"))
@require_bootstrap_key
def agent_enroll():
    """
    AD/GPO orqali avtomatik joylashtirilayotgan har bir yangi kompyuter
    uchun ALOHIDA, `/api-tokens` sahifasida ko'rinadigan va bekor
    qilinadigan API token chiqaradi.

    So'rov: {"hostname": "ACCOUNTING-PC"}
    Javob:  {"token": "nssk_...", "hostname": "ACCOUNTING-PC"}

    MUHIM: bu endpoint `require_bootstrap_key` orqali himoyalangan - ya'ni
    chaqiruvchida ANIQ umumiy "bootstrap" `AGENT_API_KEY` bo'lishi kerak
    (boshqa hostname'ga bog'langan token bilan enroll qilib bo'lmaydi -
    xavfsizlik auditida qattiqlashtirildi). Natijada olingan token esa
    SHU KOMPYUTERGA ALOHIDA tegishli -
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
