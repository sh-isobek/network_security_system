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
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, request, Response, send_file, redirect, url_for, flash, session as flask_session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from db.database import get_session
from db.models import Device, Alert, Event, FileEvent, WebAccessLog, User, utcnow
from dashboard.auth import login_manager, UserWrapper, role_required, verify_credentials
from dashboard import mfa as mfa_module
from dashboard.audit import log_action
from crypto.field_encryption import encrypt_if_configured, decrypt_if_needed

app = Flask(__name__)
app.secret_key = os.getenv("DASHBOARD_SECRET_KEY", "change-me-in-production-" + os.urandom(8).hex())
login_manager.init_app(app)


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
        agent_cutoff = utcnow() - timedelta(minutes=AGENT_ONLINE_THRESHOLD_MINUTES)
        agents_installed = session.query(Device).filter(Device.agent_last_heartbeat.isnot(None)).count()
        agents_online = session.query(Device).filter(Device.agent_last_heartbeat >= agent_cutoff).count()
        stats = {
            "device_count": session.query(Device).count(),
            "alert_count": session.query(Alert).count(),
            "critical_count": session.query(Alert).filter(Alert.severity == "critical").count(),
            "high_count": session.query(Alert).filter(Alert.severity == "high").count(),
            "malicious_files": session.query(FileEvent).filter(FileEvent.verdict == "malicious").count(),
            "clean_files": session.query(FileEvent).filter(FileEvent.verdict == "clean").count(),
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
    session = get_session()
    try:
        severity_filter = request.args.get("severity", "")
        query = session.query(Alert)
        if severity_filter:
            query = query.filter(Alert.severity == severity_filter)
        all_alerts = query.order_by(Alert.timestamp.desc()).limit(200).all()
        alerts_data = [_alert_to_dict(session, a) for a in all_alerts]
        return render_template("alerts.html", alerts=alerts_data, severity_filter=severity_filter)
    finally:
        session.close()


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


@app.route("/devices")
@login_required
def devices():
    session = get_session()
    try:
        all_devices = session.query(Device).order_by(Device.risk_score.desc(), Device.last_seen.desc()).limit(200).all()
        devices_data = []
        for d in all_devices:
            alert_count = session.query(Alert).filter(Alert.device_id == d.id).count()
            devices_data.append({
                "id": d.id, "ip_address": d.ip_address, "mac_address": d.mac_address,
                "hostname": d.hostname, "connection_type": d.connection_type,
                "source": d.source, "last_seen": d.last_seen, "alert_count": alert_count,
                "risk_score": d.risk_score or 0,
                "agent_status": _agent_status(d.agent_last_heartbeat),
                "agent_last_heartbeat": d.agent_last_heartbeat,
                "agent_version": d.agent_version, "agent_os": d.agent_os,
            })
        return render_template("devices.html", devices=devices_data)
    finally:
        session.close()


@app.route("/agent-coverage")
@role_required("admin")
def agent_coverage_page():
    from network_discovery.agent_coverage import generate_coverage_report, STALE_THRESHOLD_HOURS
    try:
        report = generate_coverage_report()
        error = None
    except Exception as exc:
        report = None
        error = str(exc)
    return render_template("agent_coverage.html", report=report, error=error, stale_hours=STALE_THRESHOLD_HOURS)


@app.route("/asset-inventory")
@login_required
def asset_inventory():
    import json as json_mod
    from db.models import TopologyLink

    session = get_session()
    try:
        all_devices = (
            session.query(Device)
            .filter(Device.discovery_source.isnot(None))
            .order_by(Device.last_discovered_at.desc())
            .limit(300)
            .all()
        )
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

        return render_template("asset_inventory.html", devices=devices_data, topology=topology)
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
        query = session.query(FileEvent)
        if verdict_filter:
            query = query.filter(FileEvent.verdict == verdict_filter)
        if channel_filter:
            query = query.filter(FileEvent.channel == channel_filter)
        all_files = query.order_by(FileEvent.timestamp.desc()).limit(200).all()
        return render_template("files.html", files=all_files, verdict_filter=verdict_filter, channel_filter=channel_filter)
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
        all_users = session.query(User).order_by(User.username).all()
        return render_template("users.html", users=all_users)
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
    return render_template("api_tokens.html", tokens=tokens, new_token=new_token)


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
    from db.models import AuditLog
    session = get_session()
    try:
        action_filter = request.args.get("action", "")
        query = session.query(AuditLog)
        if action_filter:
            query = query.filter(AuditLog.action == action_filter)
        entries = query.order_by(AuditLog.timestamp.desc()).limit(300).all()
        return render_template("audit.html", entries=entries, action_filter=action_filter)
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
