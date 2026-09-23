"""
Web Dashboard - RBAC bilan (yangi TZ 12 va 20-bo'limlar).

Server-rendered Jinja2 shablonlar ishlatiladi (React/JS build vositalari
shart emas - ichki SOC vositasi uchun eng sodda va barqaror yechim).

Autentifikatsiya: flask_login orqali sessiya-asosli login (Basic Auth
o'rniga - foydalanuvchilarni alohida ko'rish/boshqarish imkonini beradi).

RBAC: 3 rol (admin/analyst/viewer) - dashboard/auth.py'da to'liq
tavsiflangan. Boshlang'ich admin foydalanuvchini yaratish:

    python -m dashboard.create_user --username admin --password '...' --role admin

Ishga tushirish:
    python -m dashboard.app
"""
import os
import secrets
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, Response, send_file, redirect, url_for, flash, session as flask_session, abort
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import timedelta

from db.database import get_session
from db.models import Device, Alert, Event, FileEvent, FileDecision, HashBlacklist, WebAccessLog, User, Incident, utcnow
from dashboard.auth import login_manager, UserWrapper, role_required, verify_credentials
from dashboard import mfa as mfa_module
from dashboard.audit import log_action
from crypto.field_encryption import encrypt_if_configured, decrypt_if_needed
from config.settings import DEVICE_OFFLINE_THRESHOLD_MINUTES


def _device_online_cutoff():
    """Qurilma 'onlayn/tarmoqqa ulangan' hisoblanishi uchun eng eski last_seen chegarasi."""
    return utcnow() - timedelta(minutes=DEVICE_OFFLINE_THRESHOLD_MINUTES)

app = Flask(__name__)
app.secret_key = os.getenv("DASHBOARD_SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError("DASHBOARD_SECRET_KEY majburiy: Dashboard ishga tushirilmadi")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
)
login_manager.init_app(app)


@app.context_processor
def csrf_context():
    """Har brauzer sessiyasi uchun tasodifiy CSRF tokenini template'larga beradi."""
    token = flask_session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {"csrf_token": token}


@app.before_request
def protect_post_requests():
    # Login/MFA-verification hali autentifikatsiyadan o'tmagan oqimlar;
    # ular sessiya huquqini o'zgartirmaydi. Barcha autentifikatsiyalangan
    # boshqaruv POST so'rovlari esa token talab qiladi.
    if request.method == "POST" and current_user.is_authenticated and not secrets.compare_digest(
        request.form.get("csrf_token", ""), flask_session.get("csrf_token", "")
    ):
        abort(400, "CSRF token noto'g'ri yoki yo'q")


@app.template_filter("local_dt")
def local_dt_filter(dt, fmt="%Y-%m-%d %H:%M:%S", fallback="-"):
    """
    UTC datetime'ni Dashboard uchun mahalliy vaqt zonasiga (`config.
    settings.TIMEZONE_OFFSET_HOURS`, standart +5 - Toshkent) o'tkazib,
    formatlaydi. MUHIM: bazada saqlangan qiymatning o'zi UTC bo'lib
    qoladi - bu faqat FOYDALANUVCHIGA KO'RSATISH uchun.

    Shablonda ishlatilishi:
        {{ alert.timestamp | local_dt }}
        {{ device.last_seen | local_dt('%Y-%m-%d %H:%M') }}
    """
    if dt is None:
        return fallback
    from datetime import timedelta
    from config.settings import TIMEZONE_OFFSET_HOURS
    local = dt + timedelta(hours=TIMEZONE_OFFSET_HOURS)
    return local.strftime(fmt)


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        session = get_session()
        try:
            user = session.query(User).filter(User.username == username).first()
            if user and user.is_active and verify_credentials(user, password):
                if user.mfa_enabled:
                    # Parol to'g'ri, lekin MFA yoqilgan - login_user() HALI
                    # chaqirilmaydi. Foydalanuvchi ID'sini vaqtinchalik
                    # sessiyada saqlab, 2-bosqichga (kod kiritish) yo'naltiramiz.
                    flask_session["pending_mfa_user_id"] = user.id
                    return redirect(url_for("mfa_verify"))

                user.last_login = utcnow()
                session.commit()
                login_user(UserWrapper(user))
                log_action(username, "login", ip_address=request.remote_addr)
                next_url = request.args.get("next") or url_for("index")
                # Faqat shu dashboard ichidagi nisbiy URL'ga qaytamiz.
                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = url_for("index")
                return redirect(next_url)
            log_action(username, "login", success=False, ip_address=request.remote_addr,
                       details="Foydalanuvchi topilmadi/faolsiz/parol noto'g'ri")
            flash("Login yoki parol noto'g'ri", "error")
        finally:
            session.close()

    return render_template("login.html")


@app.route("/mfa/verify", methods=["GET", "POST"])
def mfa_verify():
    """Login'ning 2-bosqichi: TOTP kodini tekshirish."""
    pending_user_id = flask_session.get("pending_mfa_user_id")
    if not pending_user_id:
        return redirect(url_for("login"))

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        session = get_session()
        try:
            user = session.query(User).filter(User.id == pending_user_id).first()
            decrypted_secret = decrypt_if_needed(user.mfa_secret) if user else None
            if user and mfa_module.verify_code(decrypted_secret, code):
                user.last_login = utcnow()
                session.commit()
                flask_session.pop("pending_mfa_user_id", None)
                login_user(UserWrapper(user))
                log_action(user.username, "login", details="MFA orqali", ip_address=request.remote_addr)
                return redirect(url_for("index"))
            uname = user.username if user else "nomalum"
            log_action(uname, "mfa_verify", success=False, ip_address=request.remote_addr)
            flash("Kod noto'g'ri yoki muddati o'tgan", "error")
        finally:
            session.close()

    return render_template("mfa_verify.html")


@app.route("/mfa/setup", methods=["GET", "POST"])
@login_required
def mfa_setup():
    """Joriy foydalanuvchi uchun MFA'ni yoqish (QR-kod skanerlash + tasdiqlash)."""
    session = get_session()
    try:
        user = session.query(User).filter(User.id == current_user.id).first()

        if user.mfa_enabled:
            return render_template("mfa_setup.html", already_enabled=True)

        if request.method == "POST":
            code = request.form.get("code", "").strip()
            secret = flask_session.get("pending_mfa_secret")
            if secret and mfa_module.verify_code(secret, code):
                user.mfa_secret = encrypt_if_configured(secret)
                user.mfa_enabled = True
                session.commit()
                flask_session.pop("pending_mfa_secret", None)
                flash("MFA muvaffaqiyatli yoqildi", "success")
                log_action(current_user.username, "mfa_enable", ip_address=request.remote_addr)
                return redirect(url_for("index"))
            flash("Kod noto'g'ri - qaytadan urinib ko'ring", "error")

        # Yangi vaqtinchalik maxfiy kalit (hali tasdiqlanmagan, DB'ga yozilmagan)
        secret = flask_session.get("pending_mfa_secret")
        if not secret:
            secret = mfa_module.generate_secret()
            flask_session["pending_mfa_secret"] = secret

        qr_data_uri = mfa_module.generate_qr_code_data_uri(secret, user.username)
        return render_template("mfa_setup.html", already_enabled=False, qr_data_uri=qr_data_uri, secret=secret)
    finally:
        session.close()


@app.route("/mfa/disable", methods=["POST"])
@login_required
def mfa_disable():
    session = get_session()
    try:
        user = session.query(User).filter(User.id == current_user.id).first()
        user.mfa_enabled = False
        user.mfa_secret = None
        session.commit()
        flash("MFA o'chirildi", "success")
        log_action(current_user.username, "mfa_disable", ip_address=request.remote_addr)
    finally:
        session.close()
    return redirect(url_for("index"))


@app.route("/logout")
@login_required
def logout():
    log_action(current_user.username, "logout", ip_address=request.remote_addr)
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    from datetime import timedelta
    from config.settings import AGENT_ONLINE_THRESHOLD_MINUTES

    session = get_session()
    try:
        online_cutoff = _device_online_cutoff()
        device_count = session.query(Device).count()
        online_device_count = session.query(Device).filter(Device.last_seen >= online_cutoff).count()

        agent_cutoff = utcnow() - timedelta(minutes=AGENT_ONLINE_THRESHOLD_MINUTES)
        agents_installed = session.query(Device).filter(Device.agent_last_heartbeat.isnot(None)).count()
        agents_online = session.query(Device).filter(Device.agent_last_heartbeat >= agent_cutoff).count()
        stats = {
            "device_count": device_count,
            "online_device_count": online_device_count,
            "offline_device_count": device_count - online_device_count,
            "alert_count": session.query(Alert).count(),
            "critical_count": session.query(Alert).filter(Alert.severity == "critical").count(),
            "high_count": session.query(Alert).filter(Alert.severity == "high").count(),
            "malicious_files": session.query(FileEvent).filter(FileEvent.verdict == "malicious").count(),
            "suspicious_files": session.query(FileEvent).filter(FileEvent.verdict == "suspicious").count(),
            "clean_files": session.query(FileEvent).filter(FileEvent.verdict == "clean").count(),
            "unknown_files": session.query(FileEvent).filter(FileEvent.verdict == "unknown").count(),
            "event_count": session.query(Event).count(),
            "agents_online": agents_online,
            "agents_offline": agents_installed - agents_online,
        }
        recent_alerts = session.query(Alert).order_by(Alert.timestamp.desc()).limit(10).all()
        recent_alerts_data = [_alert_to_dict(session, a) for a in recent_alerts]
        return render_template("index.html", stats=stats, recent_alerts=recent_alerts_data)
    finally:
        session.close()


@app.route("/alerts")
@login_required
def alerts():
    from datetime import datetime, time as dt_time

    session = get_session()
    try:
        severity_filter = request.args.get("severity", "")
        ack_filter = request.args.get("acknowledged", "")
        hostname_filter = request.args.get("hostname", "").strip()
        ip_filter = request.args.get("ip", "").strip()
        mitre_filter = request.args.get("mitre", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        query = session.query(Alert)
        if severity_filter:
            query = query.filter(Alert.severity == severity_filter)
        if ack_filter == "1":
            query = query.filter(Alert.acknowledged.is_(True))
        elif ack_filter == "0":
            query = query.filter(Alert.acknowledged.is_(False))
        if mitre_filter:
            query = query.filter(Alert.mitre_technique_id.ilike(f"%{mitre_filter}%"))
        if hostname_filter or ip_filter:
            query = query.join(Device, Alert.device_id == Device.id)
            if hostname_filter:
                query = query.filter(Device.hostname.ilike(f"%{hostname_filter}%"))
            if ip_filter:
                query = query.filter(Device.ip_address.ilike(f"%{ip_filter}%"))
        if date_from:
            try:
                query = query.filter(Alert.timestamp >= datetime.combine(datetime.strptime(date_from, "%Y-%m-%d").date(), dt_time.min))
            except ValueError:
                pass
        if date_to:
            try:
                query = query.filter(Alert.timestamp < datetime.combine(datetime.strptime(date_to, "%Y-%m-%d").date(), dt_time.max))
            except ValueError:
                pass

        all_alerts = query.order_by(Alert.timestamp.desc()).limit(200).all()
        alerts_data = [_alert_to_dict(session, a) for a in all_alerts]
        _attach_file_decisions(session, all_alerts, alerts_data)
        return render_template(
            "alerts.html", alerts=alerts_data, severity_filter=severity_filter,
            ack_filter=ack_filter, hostname_filter=hostname_filter, ip_filter=ip_filter,
            mitre_filter=mitre_filter, date_from=date_from, date_to=date_to,
        )
    finally:
        session.close()


def _attach_file_decisions(session, alert_objs, alert_dicts):
    """Virus deb topilgan FAYL alertlariga admin qarori tugmalari uchun sha256 va joriy qarorni biriktiradi."""
    fe_ids = [a.file_event_id for a in alert_objs if a.file_event_id]
    sha_by_fe = {}
    if fe_ids:
        sha_by_fe = dict(session.query(FileEvent.id, FileEvent.sha256).filter(FileEvent.id.in_(fe_ids)).all())
    shas = [v for v in sha_by_fe.values() if v]
    decisions = {}
    if shas:
        decisions = dict(session.query(FileDecision.sha256, FileDecision.decision).filter(FileDecision.sha256.in_(shas)).all())
    for obj, d in zip(alert_objs, alert_dicts):
        sha = sha_by_fe.get(obj.file_event_id)
        d["file_sha256"] = sha
        d["file_decision"] = decisions.get(sha)
        # tugma FAQAT virus deb topilgan (critical/high) fayl alertlarida
        d["show_decision"] = bool(sha) and obj.severity in ("critical", "high")


@app.route("/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@role_required("analyst")
def acknowledge_alert(alert_id):
    session = get_session()
    try:
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        if alert:
            alert.acknowledged = True
            alert.acknowledged_by = current_user.username
            alert.acknowledged_at = utcnow()
            session.commit()
            flash(f"Alert #{alert_id} tasdiqlandi", "success")
            log_action(current_user.username, "acknowledge_alert", target_type="Alert",
                       target_id=alert_id, ip_address=request.remote_addr)
        return redirect(request.referrer or url_for("alerts"))
    finally:
        session.close()


# ---------------------------------------------------------------------
# Correlation Engine: Incident'lar - bir necha alertni bitta hodisaga
# birlashtirgan yuqori darajali ko'rinish
# ---------------------------------------------------------------------
@app.route("/incidents")
@login_required
def incidents():
    session = get_session()
    try:
        severity_filter = request.args.get("severity", "")
        hostname_filter = request.args.get("hostname", "").strip()

        query = session.query(Incident)
        if severity_filter:
            query = query.filter(Incident.severity == severity_filter)
        if hostname_filter:
            query = query.join(Device, Incident.device_id == Device.id).filter(
                Device.hostname.ilike(f"%{hostname_filter}%")
            )

        all_incidents = query.order_by(Incident.last_seen.desc()).limit(200).all()
        incidents_data = []
        for inc in all_incidents:
            device = session.query(Device).filter(Device.id == inc.device_id).first() if inc.device_id else None
            incidents_data.append({
                "id": inc.id, "title": inc.title, "severity": inc.severity,
                "hostname": device.hostname if device else None,
                "ip_address": device.ip_address if device else None,
                "alert_count": inc.alert_count, "first_seen": inc.first_seen, "last_seen": inc.last_seen,
            })
        return render_template(
            "incidents.html", incidents=incidents_data,
            severity_filter=severity_filter, hostname_filter=hostname_filter,
        )
    finally:
        session.close()


@app.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    session = get_session()
    try:
        incident = session.query(Incident).filter(Incident.id == incident_id).first()
        if not incident:
            abort(404)
        device = session.query(Device).filter(Device.id == incident.device_id).first() if incident.device_id else None
        related_alerts = (
            session.query(Alert)
            .filter(Alert.incident_id == incident_id)
            .order_by(Alert.timestamp.asc())
            .all()
        )
        alerts_data = [_alert_to_dict(session, a) for a in related_alerts]
        incident_data = {
            "id": incident.id, "title": incident.title, "severity": incident.severity,
            "alert_count": incident.alert_count,
            "first_seen": incident.first_seen, "last_seen": incident.last_seen,
            "hostname": device.hostname if device else None,
            "ip_address": device.ip_address if device else None,
        }
        return render_template("incident_detail.html", incident=incident_data, alerts=alerts_data)
    finally:
        session.close()


def _agent_status(agent_last_heartbeat):
    """
    "online" / "offline" / None (agent umuman o'rnatilmagan - hech
    qachon heartbeat yubormagan) - `Device.agent_last_heartbeat` va
    `AGENT_ONLINE_THRESHOLD_MINUTES` asosida.
    """
    from datetime import timedelta
    from config.settings import AGENT_ONLINE_THRESHOLD_MINUTES

    if agent_last_heartbeat is None:
        return None
    cutoff = utcnow() - timedelta(minutes=AGENT_ONLINE_THRESHOLD_MINUTES)
    return "online" if agent_last_heartbeat >= cutoff else "offline"


DEVICES_PAGE_SIZE = 200


@app.route("/devices")
@login_required
def devices():
    """
    MUHIM (real production xatosi tuzatilgan): sarlavha/statistika
    kartochkalari HAQIQIY jami sonni (`total_count`, filtrsiz butun
    `devices` jadvali) ko'rsatsa-da, pastdagi jadval avval `.limit(200)`
    bilan qattiq cheklangan edi - foydalanuvchi "724 ta qurilma" deb
    o'qiydi, lekin ro'yxatda faqat birinchi 200 tasini ko'radi, qolgan
    500+ tasi HECH QACHON ko'rinmasdi (sahifalash yo'q edi). Endi
    `page` parametri orqali sahifalab, BARCHA qurilmalarga (joriy
    onlayn/offlayn filtriga mos) yetish mumkin.
    """
    from datetime import timedelta
    from sqlalchemy import or_
    from config.settings import AGENT_ONLINE_THRESHOLD_MINUTES, DEVICE_STALE_HIDE_HOURS

    session = get_session()
    try:
        online_cutoff = _device_online_cutoff()
        agent_cutoff = utcnow() - timedelta(minutes=AGENT_ONLINE_THRESHOLD_MINUTES)
        stale_cutoff = utcnow() - timedelta(hours=DEVICE_STALE_HIDE_HOURS)
        show_stale = request.args.get("show_stale", "") == "1"
        status_filter = request.args.get("status", "")
        ip_filter = request.args.get("ip", "").strip()
        mac_filter = request.args.get("mac", "").strip()
        hostname_filter = request.args.get("hostname", "").strip()
        connection_filter = request.args.get("connection_type", "").strip()
        source_filter = request.args.get("source", "").strip()
        agent_status_filter = request.args.get("agent_status", "").strip()
        min_risk_filter = request.args.get("min_risk", "").strip()
        has_alerts_filter = request.args.get("has_alerts", "").strip()
        page = request.args.get("page", 1, type=int) or 1
        if page < 1:
            page = 1
        total_count = session.query(Device).count()
        online_count = session.query(Device).filter(Device.last_seen >= online_cutoff).count()
        offline_count = total_count - online_count
        stale_count = session.query(Device).filter(
            or_(Device.last_seen.is_(None), Device.last_seen < stale_cutoff)
        ).count()

        query = session.query(Device)
        if not show_stale:
            query = query.filter(Device.last_seen.isnot(None), Device.last_seen >= stale_cutoff)
        if status_filter == "online":
            query = query.filter(Device.last_seen >= online_cutoff)
        elif status_filter == "offline":
            query = query.filter(Device.last_seen < online_cutoff)
        if ip_filter:
            query = query.filter(Device.ip_address.ilike(f"%{ip_filter}%"))
        if mac_filter:
            query = query.filter(Device.mac_address.ilike(f"%{mac_filter}%"))
        if hostname_filter:
            query = query.filter(Device.hostname.ilike(f"%{hostname_filter}%"))
        if connection_filter in {"wifi", "cable", "unknown"}:
            query = query.filter(Device.connection_type == connection_filter)
        if source_filter:
            query = query.filter(Device.source.ilike(f"%{source_filter}%"))
        if agent_status_filter == "online":
            query = query.filter(Device.agent_last_heartbeat.isnot(None), Device.agent_last_heartbeat >= agent_cutoff)
        elif agent_status_filter == "offline":
            query = query.filter(Device.agent_last_heartbeat.isnot(None), Device.agent_last_heartbeat < agent_cutoff)
        elif agent_status_filter == "none":
            query = query.filter(Device.agent_last_heartbeat.is_(None))
        if min_risk_filter.isdigit():
            query = query.filter(Device.risk_score >= int(min_risk_filter))
        if has_alerts_filter == "1":
            query = query.filter(session.query(Alert).filter(Alert.device_id == Device.id).exists())

        filtered_count = query.count()
        total_pages = max(1, (filtered_count + DEVICES_PAGE_SIZE - 1) // DEVICES_PAGE_SIZE)
        if page > total_pages:
            page = total_pages
        all_devices = (
            query.order_by(Device.risk_score.desc(), Device.last_seen.desc())
            .offset((page - 1) * DEVICES_PAGE_SIZE)
            .limit(DEVICES_PAGE_SIZE)
            .all()
        )

        devices_data = []
        for d in all_devices:
            alert_count = session.query(Alert).filter(Alert.device_id == d.id).count()
            is_online = bool(d.last_seen and d.last_seen >= online_cutoff)
            devices_data.append({
                "id": d.id, "ip_address": d.ip_address, "mac_address": d.mac_address,
                "hostname": d.hostname, "connection_type": d.connection_type,
                "source": d.source, "last_seen": d.last_seen, "alert_count": alert_count,
                "risk_score": d.risk_score or 0, "is_online": is_online,
                "agent_status": _agent_status(d.agent_last_heartbeat),
                "agent_last_heartbeat": d.agent_last_heartbeat,
                "agent_version": d.agent_version, "agent_os": d.agent_os,
                "agent_restart_requested_at": d.agent_restart_requested_at,
            })
        return render_template(
            "devices.html", devices=devices_data, status_filter=status_filter,
            total_count=total_count, online_count=online_count, offline_count=offline_count,
            page=page, total_pages=total_pages, filtered_count=filtered_count,
            ip_filter=ip_filter, mac_filter=mac_filter, hostname_filter=hostname_filter,
            connection_filter=connection_filter, source_filter=source_filter,
            agent_status_filter=agent_status_filter, min_risk_filter=min_risk_filter,
            has_alerts_filter=has_alerts_filter,
            show_stale=show_stale, stale_count=stale_count, stale_hide_hours=DEVICE_STALE_HIDE_HOURS,
        )
    finally:
        session.close()


@app.route("/devices/<int:device_id>/request_agent_restart", methods=["POST"])
@role_required("analyst")
def request_agent_restart(device_id):
    """
    "Qayta ulanishga urinish" tugmasi (tarmoqda ONLAYN, lekin Endpoint
    Agent OFFLAYN bo'lgan qurilmalar uchun - masalan kompyuter qayta
    yoqilgandan keyin agent xizmati avtomatik boshlanmagan holat).

    Serverning o'zi qurilmaga HECH QACHON ulanmaydi/buyruq yubormaydi -
    bu shunchaki bir bayroqni (`Device.agent_restart_requested_at`)
    o'rnatadi. Shu kompyuterda GPO orqali o'rnatilgan, ASOSIY agent
    xizmatidan MUSTAQIL "watchdog" Scheduled Task (xizmat o'zi o'lik
    bo'lsa ham har necha daqiqada ishlaydi) bu bayroqni o'zi so'rab
    ko'radi (`/api/v1/agent_watchdog_check`) va True bo'lsa xizmatni
    majburiy qayta ishga tushiradi.
    """
    session = get_session()
    try:
        device = session.query(Device).filter(Device.id == device_id).first()
        if device is None:
            abort(404)
        device.agent_restart_requested_at = utcnow()
        device.agent_restart_requested_by = current_user.username
        session.commit()
        log_action(current_user.username, "request_agent_restart", target_type="Device",
                   target_id=device_id, details=device.hostname, ip_address=request.remote_addr)
        flash(f"So'ralindi: {device.hostname or device.ip_address} - mahalliy watchdog vazifasi "
              f"keyingi tekshiruvida (bir necha daqiqa ichida) xizmatni qayta ishga tushiradi.", "success")
        return redirect(request.referrer or url_for("devices"))
    finally:
        session.close()


@app.route("/agent-coverage")
@role_required("admin")
def agent_coverage_page():
    from network_discovery.agent_coverage import generate_coverage_report, STALE_THRESHOLD_HOURS
    q = request.args.get("q", "").strip().lower()
    try:
        report = generate_coverage_report()
        error = None
    except Exception as exc:
        report = None
        error = str(exc)

    missing_filtered = stale_filtered = []
    if report is not None:
        missing_filtered = [n for n in report.missing if q in n.lower()] if q else report.missing
        stale_filtered = [n for n in report.stale if q in n.lower()] if q else report.stale

    return render_template(
        "agent_coverage.html", report=report, error=error, stale_hours=STALE_THRESHOLD_HOURS,
        q=q, missing_filtered=missing_filtered, stale_filtered=stale_filtered,
    )


@app.route("/asset-inventory")
@login_required
def asset_inventory():
    import json as json_mod
    from db.models import TopologyLink

    session = get_session()
    try:
        ip_filter = request.args.get("ip", "").strip()
        mac_filter = request.args.get("mac", "").strip()
        hostname_filter = request.args.get("hostname", "").strip()
        device_type_filter = request.args.get("device_type", "").strip()
        vendor_filter = request.args.get("vendor", "").strip()
        discovery_source_filter = request.args.get("discovery_source", "").strip()

        query = session.query(Device).filter(Device.discovery_source.isnot(None))
        if ip_filter:
            query = query.filter(Device.ip_address.ilike(f"%{ip_filter}%"))
        if mac_filter:
            query = query.filter(Device.mac_address.ilike(f"%{mac_filter}%"))
        if hostname_filter:
            query = query.filter(Device.hostname.ilike(f"%{hostname_filter}%"))
        if device_type_filter:
            query = query.filter(Device.device_type == device_type_filter)
        if vendor_filter:
            query = query.filter(Device.vendor.ilike(f"%{vendor_filter}%"))
        if discovery_source_filter:
            query = query.filter(Device.discovery_source == discovery_source_filter)

        all_devices = query.order_by(Device.last_discovered_at.desc()).limit(300).all()
        devices_data = []
        for d in all_devices:
            open_ports = []
            if d.open_ports:
                try:
                    open_ports = json_mod.loads(d.open_ports)
                except (json_mod.JSONDecodeError, TypeError):
                    pass
            devices_data.append({
                "ip_address": d.ip_address, "mac_address": d.mac_address, "hostname": d.hostname,
                "device_type": d.device_type or "unknown", "vendor": d.vendor, "os_guess": d.os_guess,
                "discovery_source": d.discovery_source, "last_discovered_at": d.last_discovered_at,
                "open_ports": open_ports,
            })

        topology = session.query(TopologyLink).order_by(TopologyLink.discovered_at.desc()).limit(100).all()

        return render_template(
            "asset_inventory.html", devices=devices_data, topology=topology,
            ip_filter=ip_filter, mac_filter=mac_filter, hostname_filter=hostname_filter,
            device_type_filter=device_type_filter, vendor_filter=vendor_filter,
            discovery_source_filter=discovery_source_filter,
        )
    finally:
        session.close()


@app.route("/web-activity")
@login_required
def web_activity():
    """Qurilma -> sayt/domen -> vaqt bo'yicha qidiriladigan web faoliyat."""
    session = get_session()
    try:
        ip_filter = request.args.get("ip", "").strip()
        domain_filter = request.args.get("site", "").strip().lower()
        hostname_filter = request.args.get("hostname", "").strip()
        protocol_filter = request.args.get("protocol", "").strip().upper()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        query = session.query(WebAccessLog, Device).join(Device, WebAccessLog.device_id == Device.id)
        if ip_filter:
            query = query.filter(WebAccessLog.source_ip == ip_filter)
        if domain_filter:
            query = query.filter(WebAccessLog.domain.ilike(f"%{domain_filter}%"))
        if hostname_filter:
            query = query.filter(Device.hostname.ilike(f"%{hostname_filter}%"))
        if protocol_filter in {"HTTP", "HTTPS", "DNS"}:
            query = query.filter(WebAccessLog.protocol == protocol_filter)

        from datetime import datetime, time as dt_time
        if date_from:
            try:
                query = query.filter(WebAccessLog.timestamp >= datetime.combine(datetime.strptime(date_from, "%Y-%m-%d").date(), dt_time.min))
            except ValueError:
                pass
        if date_to:
            try:
                query = query.filter(WebAccessLog.timestamp < datetime.combine(datetime.strptime(date_to, "%Y-%m-%d").date(), dt_time.max))
            except ValueError:
                pass

        rows = query.order_by(WebAccessLog.timestamp.desc()).limit(1000).all()
        data = []
        for log, device in rows:
            data.append({
                "timestamp": log.timestamp, "ip": log.source_ip, "hostname": device.hostname,
                "domain": log.domain, "url": log.url, "method": log.method,
                "status_code": log.status_code, "protocol": log.protocol,
                "dest_ip": log.dest_ip,
            })

        return render_template(
            "web_activity.html", rows=data, ip_filter=ip_filter, site_filter=domain_filter,
            hostname_filter=hostname_filter, protocol_filter=protocol_filter,
            date_from=date_from, date_to=date_to,
        )
    finally:
        session.close()



@app.route("/files")
@login_required
def files():
    session = get_session()
    try:
        verdict_filter = request.args.get("verdict", "")
        channel_filter = request.args.get("channel", "")
        filename_filter = request.args.get("filename", "").strip()
        path_filter = request.args.get("path", "").strip()
        ip_filter = request.args.get("ip", "").strip()
        sha256_filter = request.args.get("sha256", "").strip()

        query = session.query(FileEvent)
        if verdict_filter:
            query = query.filter(FileEvent.verdict == verdict_filter)
        if channel_filter:
            query = query.filter(FileEvent.channel == channel_filter)
        if filename_filter:
            query = query.filter(FileEvent.filename.ilike(f"%{filename_filter}%"))
        if path_filter:
            query = query.filter(FileEvent.device_file_path.ilike(f"%{path_filter}%"))
        if ip_filter:
            query = query.filter(FileEvent.src_ip.ilike(f"%{ip_filter}%"))
        if sha256_filter:
            query = query.filter(FileEvent.sha256.ilike(f"{sha256_filter}%"))

        all_files = query.order_by(FileEvent.timestamp.desc()).limit(200).all()
        _shas = [f.sha256 for f in all_files if f.sha256]
        file_decisions = dict(session.query(FileDecision.sha256, FileDecision.decision).filter(FileDecision.sha256.in_(_shas)).all()) if _shas else {}
        return render_template(
            "files.html", files=all_files, file_decisions=file_decisions, verdict_filter=verdict_filter, channel_filter=channel_filter,
            filename_filter=filename_filter, path_filter=path_filter, ip_filter=ip_filter, sha256_filter=sha256_filter,
        )
    finally:
        session.close()


@app.route("/files/decision", methods=["POST"])
@role_required("analyst")
def file_decision():
    """
    Admin qarori (SHA256 bo'yicha, BARCHA qurilmalar uchun):
      safe      - "virus emas": hech qayerda chora ko'rilmaydi, oldingi qora ro'yxat yozuvlari olib tashlanadi;
      malicious - "virusni o'chirish": istalgan qurilmada aniqlansa o'chiriladi va karantinga olinadi.
    """
    sha = (request.form.get("sha256") or "").lower().strip()
    decision = request.form.get("decision")
    if len(sha) != 64 or decision not in ("safe", "malicious"):
        flash("Noto'g'ri so'rov", "error")
        return redirect(request.referrer or url_for("files"))
    session = get_session()
    try:
        fe = session.query(FileEvent).filter(FileEvent.sha256 == sha).order_by(FileEvent.id.desc()).first()
        row = session.query(FileDecision).filter_by(sha256=sha).first()
        if row is None:
            row = FileDecision(sha256=sha)
            session.add(row)
        row.decision = decision
        row.filename = fe.filename if fe else None
        row.decided_by = current_user.username
        row.decided_at = utcnow()
        row.note = f"Admin ({current_user.username}) zararli deb belgiladi"[:500] if decision == "malicious" else "Admin zararsiz deb belgiladi"

        session.query(FileEvent).filter(FileEvent.sha256 == sha).update(
            {"verdict": "clean" if decision == "safe" else "malicious"}, synchronize_session=False)
        bl = session.query(HashBlacklist).filter_by(sha256=sha)
        if decision == "safe":
            bl.delete(synchronize_session=False)
        elif bl.first() is None:
            session.add(HashBlacklist(sha256=sha, threat_name=row.note, source="admin"))

        note = ("ADMIN: zararsiz deb belgilandi (" if decision == "safe" else "ADMIN: virus deb belgilandi - o'chirish/karantin qo'llanadi (") + current_user.username + ")"
        for a in session.query(Alert).filter(Alert.reason.like(f"%SHA256={sha}%")).all():
            a.action_taken = ((a.action_taken or "") + " | " + note).strip(" |")
            a.acknowledged = True
            a.acknowledged_by = current_user.username
            a.acknowledged_at = utcnow()
        session.commit()
        log_action(current_user.username, "file_decision", target_type="File", details=f"{decision} sha256={sha}",
                   ip_address=request.remote_addr)
        flash("Qaror saqlandi: " + ("zararsiz" if decision == "safe" else "virus (barcha qurilmalarda o'chiriladi)"), "success")
        return redirect(request.referrer or url_for("files"))
    finally:
        session.close()


@app.route("/reports/download")
@login_required
def download_report():
    import tempfile
    from reports.report_generator import generate_report

    period_days = int(request.args.get("period_days", "7"))
    fmt = request.args.get("format", "csv")
    if fmt not in ("csv", "json", "pdf", "excel"):
        return Response("Noto'g'ri format - csv/json/pdf/excel bo'lishi kerak", 400)

    with tempfile.TemporaryDirectory() as tmp_dir:
        result = generate_report(period_days, [fmt], tmp_dir)
        filepath = result[fmt]
        if not filepath:
            return Response("Hisobot yaratilmadi", 500)
        log_action(current_user.username, "download_report", details=f"format={fmt}, period_days={period_days}",
                   ip_address=request.remote_addr)
        return send_file(filepath, as_attachment=True, download_name=os.path.basename(filepath))


# --- Foydalanuvchi boshqaruvi (faqat admin) ---

@app.route("/users")
@role_required("admin")
def users():
    session = get_session()
    try:
        username_filter = request.args.get("username", "").strip()
        role_filter = request.args.get("role", "").strip()
        active_filter = request.args.get("active", "").strip()

        query = session.query(User)
        if username_filter:
            query = query.filter(User.username.ilike(f"%{username_filter}%"))
        if role_filter in {"admin", "analyst", "viewer"}:
            query = query.filter(User.role == role_filter)
        if active_filter == "1":
            query = query.filter(User.is_active.is_(True))
        elif active_filter == "0":
            query = query.filter(User.is_active.is_(False))

        all_users = query.order_by(User.username).all()
        return render_template(
            "users.html", users=all_users, username_filter=username_filter,
            role_filter=role_filter, active_filter=active_filter,
        )
    finally:
        session.close()


@app.route("/users/create", methods=["POST"])
@role_required("admin")
def create_user_route():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")

    if not username or not password or role not in ("admin", "analyst", "viewer"):
        flash("Noto'g'ri ma'lumot kiritildi", "error")
        return redirect(url_for("users"))

    session = get_session()
    try:
        if session.query(User).filter(User.username == username).first():
            flash(f"'{username}' allaqachon mavjud", "error")
            return redirect(url_for("users"))
        user = User(username=username, password_hash=generate_password_hash(password), role=role)
        session.add(user)
        session.commit()
        flash(f"Foydalanuvchi '{username}' ({role}) yaratildi", "success")
        log_action(current_user.username, "create_user", target_type="User", target_id=username,
                   details=f"role={role}", ip_address=request.remote_addr)
    finally:
        session.close()
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/deactivate", methods=["POST"])
@role_required("admin")
def deactivate_user(user_id):
    session = get_session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            if user.username == current_user.username:
                flash("O'zingizni faolsizlantira olmaysiz", "error")
            else:
                user.is_active = False
                session.commit()
                flash(f"'{user.username}' faolsizlantirildi", "success")
                log_action(current_user.username, "deactivate_user", target_type="User",
                           target_id=user.username, ip_address=request.remote_addr)
    finally:
        session.close()
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/activate", methods=["POST"])
@role_required("admin")
def activate_user(user_id):
    session = get_session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if user:
            user.is_active = True
            session.commit()
            flash(f"'{user.username}' faollashtirildi", "success")
            log_action(current_user.username, "activate_user", target_type="User",
                       target_id=user.username, ip_address=request.remote_addr)
        else:
            flash("Foydalanuvchi topilmadi", "error")
    finally:
        session.close()
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/edit", methods=["POST"])
@role_required("admin")
def edit_user(user_id):
    """
    Foydalanuvchining rolini o'zgartirish va/yoki parolini tiklash.
    Login (username) o'zgartirilmaydi - bu identifikator sifatida
    (audit log, ApiToken.created_by va h.k.) ishlatiladi.
    """
    new_role = request.form.get("role", "")
    new_password = request.form.get("password", "").strip()

    if new_role not in ("admin", "analyst", "viewer"):
        flash("Noto'g'ri rol", "error")
        return redirect(url_for("users"))

    session = get_session()
    try:
        user = session.query(User).filter(User.id == user_id).first()
        if not user:
            flash("Foydalanuvchi topilmadi", "error")
            return redirect(url_for("users"))

        changes = []
        if user.role != new_role:
            if user.username == current_user.username and new_role != "admin":
                flash("O'zingizning admin rolingizni o'zgartira olmaysiz (o'zingizni qulflab qo'yish xavfi)", "error")
                return redirect(url_for("users"))
            user.role = new_role
            changes.append(f"rol -> {new_role}")

        if new_password:
            user.password_hash = generate_password_hash(new_password)
            changes.append("parol tiklandi")

        if changes:
            session.commit()
            flash(f"'{user.username}' yangilandi: {', '.join(changes)}", "success")
            log_action(current_user.username, "edit_user", target_type="User",
                       target_id=user.username, details=", ".join(changes),
                       ip_address=request.remote_addr)
        else:
            flash("Hech narsa o'zgartirilmadi", "success")
    finally:
        session.close()
    return redirect(url_for("users"))


def _alert_to_dict(session, alert: Alert) -> dict:
    device = session.query(Device).filter(Device.id == alert.device_id).first() if alert.device_id else None
    return {
        "id": alert.id,
        "timestamp": alert.timestamp,
        "severity": alert.severity,
        "reason": alert.reason,
        "action_taken": alert.action_taken,
        "notified": alert.notified,
        "mitre_technique_id": alert.mitre_technique_id,
        "mitre_technique_name": alert.mitre_technique_name,
        "mitre_tactic": alert.mitre_tactic,
        "hostname": device.hostname if device else None,
        "ip_address": device.ip_address if device else None,
        "acknowledged": alert.acknowledged,
        "acknowledged_by": alert.acknowledged_by,
    }


@app.template_filter("severity_color")
def severity_color(severity):
    return {
        "critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f", "low": "#95a5a6",
    }.get(severity, "#7f8c8d")


@app.route("/api-tokens")
@role_required("admin")
def api_tokens():
    from api import token_manager
    tokens = token_manager.list_tokens()
    new_token = flask_session.pop("new_token_plaintext", None)
    flask_session.modified = True

    name_filter = request.args.get("name", "").strip().lower()
    hostname_filter = request.args.get("hostname", "").strip().lower()
    status_filter = request.args.get("status", "").strip()
    if name_filter:
        tokens = [t for t in tokens if name_filter in (t.name or "").lower()]
    if hostname_filter:
        tokens = [t for t in tokens if hostname_filter in (t.agent_hostname or "").lower()]
    if status_filter == "active":
        tokens = [t for t in tokens if not t.revoked]
    elif status_filter == "revoked":
        tokens = [t for t in tokens if t.revoked]

    return render_template(
        "api_tokens.html", tokens=tokens, new_token=new_token,
        name_filter=name_filter, hostname_filter=hostname_filter, status_filter=status_filter,
    )


@app.route("/api-tokens/create", methods=["POST"])
@role_required("admin")
def api_tokens_create():
    from api import token_manager
    name = request.form.get("name", "").strip()
    expires_days = request.form.get("expires_days", "").strip()
    if not name:
        flash("Token nomi majburiy", "error")
        return redirect(url_for("api_tokens"))

    token = token_manager.create_token(
        name, created_by=current_user.username,
        expires_days=int(expires_days) if expires_days else None,
    )
    flask_session["new_token_plaintext"] = token
    log_action(current_user.username, "create_api_token", target_type="ApiToken", target_id=name,
               ip_address=request.remote_addr)
    return redirect(url_for("api_tokens"))


@app.route("/api-tokens/<int:token_id>/revoke", methods=["POST"])
@role_required("admin")
def api_tokens_revoke(token_id):
    from api import token_manager
    ok = token_manager.revoke_token(token_id)
    if ok:
        flash("Token bekor qilindi", "success")
        log_action(current_user.username, "revoke_api_token", target_type="ApiToken", target_id=token_id,
                   ip_address=request.remote_addr)
    return redirect(url_for("api_tokens"))


@app.route("/audit")
@role_required("admin")
def audit_log():
    from datetime import datetime, time as dt_time
    from db.models import AuditLog
    session = get_session()
    try:
        action_filter = request.args.get("action", "")
        username_filter = request.args.get("username", "").strip()
        target_type_filter = request.args.get("target_type", "").strip()
        ip_filter = request.args.get("ip", "").strip()
        date_from = request.args.get("date_from", "").strip()
        date_to = request.args.get("date_to", "").strip()

        query = session.query(AuditLog)
        if action_filter:
            query = query.filter(AuditLog.action == action_filter)
        if username_filter:
            query = query.filter(AuditLog.username.ilike(f"%{username_filter}%"))
        if target_type_filter:
            query = query.filter(AuditLog.target_type.ilike(f"%{target_type_filter}%"))
        if ip_filter:
            query = query.filter(AuditLog.ip_address.ilike(f"%{ip_filter}%"))
        if date_from:
            try:
                query = query.filter(AuditLog.timestamp >= datetime.combine(datetime.strptime(date_from, "%Y-%m-%d").date(), dt_time.min))
            except ValueError:
                pass
        if date_to:
            try:
                query = query.filter(AuditLog.timestamp < datetime.combine(datetime.strptime(date_to, "%Y-%m-%d").date(), dt_time.max))
            except ValueError:
                pass

        entries = query.order_by(AuditLog.timestamp.desc()).limit(300).all()
        return render_template(
            "audit.html", entries=entries, action_filter=action_filter,
            username_filter=username_filter, target_type_filter=target_type_filter,
            ip_filter=ip_filter, date_from=date_from, date_to=date_to,
        )
    finally:
        session.close()


@app.route("/live-map")
@login_required
def live_map():
    return render_template("live_map.html")


@app.route("/api/topology")
@login_required
def api_topology():
    """
    Live Map uchun tarmoq topologiyasi ma'lumoti (JSON).
    Nodes - so'nggi 24 soatda faol bo'lgan qurilmalar (risk_score bo'yicha
    rangli). Edges - shu qurilmalar orasidagi/ular bilan tashqi manzillar
    orasidagi aloqalar (hodisalar soni bo'yicha og'irlangan).
    """
    from datetime import timedelta
    from sqlalchemy import func

    session = get_session()
    try:
        since = utcnow() - timedelta(hours=24)

        active_device_ids = (
            session.query(Event.device_id)
            .filter(Event.timestamp >= since)
            .distinct()
            .limit(100)
            .all()
        )
        device_ids = [d[0] for d in active_device_ids if d[0] is not None]

        devices = session.query(Device).filter(Device.id.in_(device_ids)).all() if device_ids else []

        nodes = []
        for d in devices:
            risk = d.risk_score or 0
            if risk >= 70:
                color = "#c0392b"
            elif risk >= 30:
                color = "#e67e22"
            elif risk > 0:
                color = "#f1c40f"
            else:
                color = "#3498db"
            nodes.append({
                "id": f"dev_{d.id}",
                "label": d.hostname or d.ip_address,
                "title": f"{d.ip_address} | risk={risk} | {d.connection_type or 'nomalum'}",
                "color": color,
                "shape": "dot",
                "size": 14 + min(risk, 100) / 5,
            })

        # Edges: qurilma -> tashqi manzil (dest_ip), so'nggi 24 soatda,
        # eng ko'p uchraydigan 60 ta juftlik bilan cheklangan (grafik
        # o'qilishini saqlash uchun)
        edge_rows = []
        if device_ids:
            edge_rows = (
                session.query(Event.device_id, Event.dest_ip, func.count(Event.id).label("cnt"))
                .filter(Event.timestamp >= since, Event.device_id.in_(device_ids))
                .group_by(Event.device_id, Event.dest_ip)
                .order_by(func.count(Event.id).desc())
                .limit(60)
                .all()
            )

        edges = []
        external_nodes = {}
        for device_id, dest_ip, cnt in edge_rows:
            if not dest_ip:
                continue
            dest_node_id = f"ext_{dest_ip}"
            if dest_node_id not in external_nodes:
                external_nodes[dest_node_id] = {
                    "id": dest_node_id, "label": dest_ip, "shape": "dot",
                    "color": "#95a5a6", "size": 8,
                }
            edges.append({
                "from": f"dev_{device_id}", "to": dest_node_id,
                "value": cnt, "title": f"{cnt} ta hodisa",
            })

        nodes.extend(external_nodes.values())

        return {"nodes": nodes, "edges": edges}
    finally:
        session.close()


@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Bu sahifaga kirish huquqingiz yo'q"), 403


if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", "8080"))
    app.run(host="0.0.0.0", port=port)
