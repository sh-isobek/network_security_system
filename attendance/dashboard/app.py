"""
Davomat Dashboard - RBAC bilan (super_admin / hr_admin / viewer).

Ishga tushirish:
    python -m attendance.dashboard.create_user --username admin --password '...' --role super_admin
    python -m attendance.dashboard.app          # http://localhost:8090
"""
import os
import secrets
import sys
from datetime import date, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from flask import (
    Flask, render_template, request, redirect, url_for, flash, abort,
    session as flask_session,
)
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash

from attendance.database import get_session
from attendance.models import (
    Employee, AttendanceUser, AttendanceAuditLog, Penalty, WorkSchedule,
    DailyAttendance, ALL_ROLES, ROLE_SUPER_ADMIN, ROLE_HR_ADMIN, ROLE_VIEWER, utcnow,
)
from attendance.dashboard.auth import (
    login_manager, UserWrapper, role_required, super_admin_only, verify_credentials,
)
from attendance.dashboard.audit import log_action
from attendance.stats import compute_period_stats, late_and_absent_for_date
from attendance.calculator import get_or_create_default_schedule

app = Flask(__name__)
app.secret_key = os.getenv("ATTENDANCE_DASHBOARD_SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError("ATTENDANCE_DASHBOARD_SECRET_KEY majburiy: Dashboard ishga tushirilmadi")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true",
    SESSION_COOKIE_SAMESITE="Lax",
)
login_manager.init_app(app)


@app.context_processor
def csrf_context():
    token = flask_session.setdefault("csrf_token", secrets.token_urlsafe(32))
    return {"csrf_token": token, "current_role": getattr(current_user, "role", None)}


@app.before_request
def protect_post_requests():
    if request.method == "POST" and current_user.is_authenticated and not secrets.compare_digest(
        request.form.get("csrf_token", ""), flask_session.get("csrf_token", "")
    ):
        abort(400, "CSRF token noto'g'ri yoki yo'q")


def _period_range(period: str):
    today = date.today()
    if period == "today":
        return today, today
    if period == "month":
        return today.replace(day=1), today
    # standart: hafta (oxirgi 7 kun)
    return today - timedelta(days=6), today


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        session = get_session()
        try:
            user = session.query(AttendanceUser).filter_by(username=username).first()
            if user and user.is_active and verify_credentials(user, password):
                user.last_login = utcnow()
                session.commit()
                login_user(UserWrapper(user))
                log_action(username, user.role, "login", ip_address=request.remote_addr)
                next_url = request.args.get("next") or url_for("index")
                if not next_url.startswith("/") or next_url.startswith("//"):
                    next_url = url_for("index")
                return redirect(next_url)
            log_action(username, None, "login", success=False, ip_address=request.remote_addr,
                       details="Foydalanuvchi topilmadi/faolsiz/parol noto'g'ri")
            flash("Login yoki parol noto'g'ri", "error")
        finally:
            session.close()

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    log_action(current_user.username, current_user.role, "logout")
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def index():
    period = request.args.get("period", "week")
    start_date, end_date = _period_range(period)
    department = request.args.get("department") or None

    session = get_session()
    try:
        stats = compute_period_stats(session, start_date, end_date, department=department)
        departments = [
            d[0] for d in session.query(Employee.department).filter(Employee.department.isnot(None)).distinct().all()
        ]
    finally:
        session.close()

    return render_template(
        "index.html", stats=stats, period=period, start_date=start_date, end_date=end_date,
        departments=departments, selected_department=department,
    )


@app.route("/employees")
@role_required(ROLE_HR_ADMIN)
def employees():
    q = request.args.get("q", "").strip()
    session = get_session()
    try:
        query = session.query(Employee)
        if q:
            like = f"%{q}%"
            query = query.filter(
                (Employee.full_name.ilike(like)) |
                (Employee.employee_no.ilike(like)) |
                (Employee.department.ilike(like))
            )
        emp_list = query.order_by(Employee.full_name.asc()).all()
        schedules = session.query(WorkSchedule).all()
    finally:
        session.close()
    return render_template("employees.html", employees=emp_list, schedules=schedules, q=q)


@app.route("/employees/add", methods=["POST"])
@super_admin_only
def employee_add():
    employee_no = request.form.get("employee_no", "").strip()
    full_name = request.form.get("full_name", "").strip()
    department = request.form.get("department", "").strip() or None
    position = request.form.get("position", "").strip() or None

    if not employee_no or not full_name:
        flash("Xodim raqami va F.I.Sh majburiy", "error")
        return redirect(url_for("employees"))

    session = get_session()
    try:
        if session.query(Employee).filter_by(employee_no=employee_no).first():
            flash(f"'{employee_no}' raqamli xodim allaqachon mavjud", "error")
            return redirect(url_for("employees"))
        emp = Employee(employee_no=employee_no, full_name=full_name, department=department,
                        position=position, is_active=True)
        session.add(emp)
        session.commit()
        log_action(current_user.username, current_user.role, "employee_add",
                    target_type="employee", target_id=employee_no,
                    details=full_name, ip_address=request.remote_addr)
        flash(f"Xodim qo'shildi: {full_name}", "success")
    finally:
        session.close()
    return redirect(url_for("employees"))


@app.route("/employees/<int:employee_id>/delete", methods=["POST"])
@super_admin_only
def employee_delete(employee_id):
    session = get_session()
    try:
        emp = session.query(Employee).filter_by(id=employee_id).first()
        if not emp:
            abort(404)
        name = emp.full_name
        session.delete(emp)
        session.commit()
        log_action(current_user.username, current_user.role, "employee_delete",
                    target_type="employee", target_id=employee_id,
                    details=name, ip_address=request.remote_addr)
        flash(f"Xodim o'chirildi: {name}", "success")
    finally:
        session.close()
    return redirect(url_for("employees"))


@app.route("/employees/<int:employee_id>/edit", methods=["POST"])
@role_required(ROLE_HR_ADMIN)
def employee_edit(employee_id):
    session = get_session()
    try:
        emp = session.query(Employee).filter_by(id=employee_id).first()
        if not emp:
            abort(404)
        emp.full_name = request.form.get("full_name", emp.full_name).strip() or emp.full_name
        emp.department = request.form.get("department", "").strip() or None
        emp.position = request.form.get("position", "").strip() or None
        emp.is_active = request.form.get("is_active") == "on"
        session.commit()
        log_action(current_user.username, current_user.role, "employee_edit",
                    target_type="employee", target_id=employee_id,
                    details=emp.full_name, ip_address=request.remote_addr)
        flash(f"Xodim ma'lumotlari yangilandi: {emp.full_name}", "success")
    finally:
        session.close()
    return redirect(url_for("employees"))


@app.route("/reports")
@role_required(ROLE_HR_ADMIN)
def reports():
    period = request.args.get("period", "month")
    start_date, end_date = _period_range(period)
    if request.args.get("start"):
        start_date = date.fromisoformat(request.args["start"])
    if request.args.get("end"):
        end_date = date.fromisoformat(request.args["end"])

    session = get_session()
    try:
        records = (
            session.query(DailyAttendance)
            .join(Employee)
            .filter(
                DailyAttendance.work_date >= start_date,
                DailyAttendance.work_date <= end_date,
                DailyAttendance.arrival_status.isnot(None),
            )
            .order_by(DailyAttendance.work_date.desc())
            .all()
        )
        per_employee = {}
        for r in records:
            key = r.employee_id
            if key not in per_employee:
                per_employee[key] = {"employee": r.employee, "late": 0, "absent": 0, "total_late_minutes": 0}
            if r.arrival_status == "kechikdi":
                per_employee[key]["late"] += 1
                per_employee[key]["total_late_minutes"] += r.late_minutes
            elif r.arrival_status == "kelmadi":
                per_employee[key]["absent"] += 1
    finally:
        session.close()

    summary = sorted(per_employee.values(), key=lambda x: (-x["late"] - x["absent"]))
    return render_template("reports.html", summary=summary, start_date=start_date, end_date=end_date, period=period)


@app.route("/penalties")
@role_required(ROLE_HR_ADMIN)
def penalties():
    session = get_session()
    try:
        rows = session.query(Penalty).order_by(Penalty.issued_at.desc()).limit(200).all()
        emp_list = session.query(Employee).filter_by(is_active=True).order_by(Employee.full_name.asc()).all()
    finally:
        session.close()
    return render_template("penalties.html", penalties=rows, employees=emp_list)


@app.route("/penalties/add", methods=["POST"])
@role_required(ROLE_HR_ADMIN)
def penalty_add():
    employee_id = request.form.get("employee_id", type=int)
    penalty_type = request.form.get("penalty_type", "ogohlantirish")
    amount = request.form.get("amount", type=float)
    reason = request.form.get("reason", "").strip()

    session = get_session()
    try:
        emp = session.query(Employee).filter_by(id=employee_id).first()
        if not emp:
            abort(404)
        row = Penalty(
            employee_id=employee_id, penalty_type=penalty_type,
            amount=amount if penalty_type == "jarima" else None,
            reason=reason, issued_by=current_user.username,
        )
        session.add(row)
        session.commit()
        log_action(current_user.username, current_user.role, "penalty_add",
                    target_type="employee", target_id=employee_id,
                    details=f"{penalty_type}: {reason}", ip_address=request.remote_addr)
        flash(f"{emp.full_name} uchun {penalty_type} belgilandi", "success")
    finally:
        session.close()
    return redirect(url_for("penalties"))


@app.route("/users")
@super_admin_only
def users():
    session = get_session()
    try:
        rows = session.query(AttendanceUser).order_by(AttendanceUser.username.asc()).all()
    finally:
        session.close()
    return render_template("users.html", users=rows, roles=ALL_ROLES)


@app.route("/users/add", methods=["POST"])
@super_admin_only
def user_add():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", ROLE_VIEWER)

    if not username or not password or role not in ALL_ROLES:
        flash("Noto'g'ri ma'lumot", "error")
        return redirect(url_for("users"))

    session = get_session()
    try:
        if session.query(AttendanceUser).filter_by(username=username).first():
            flash(f"'{username}' allaqachon mavjud", "error")
            return redirect(url_for("users"))
        user = AttendanceUser(username=username, password_hash=generate_password_hash(password),
                               role=role, is_active=True)
        session.add(user)
        session.commit()
        log_action(current_user.username, current_user.role, "user_add",
                    target_type="user", target_id=username, details=role,
                    ip_address=request.remote_addr)
        flash(f"Foydalanuvchi yaratildi: {username}", "success")
    finally:
        session.close()
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/deactivate", methods=["POST"])
@super_admin_only
def user_deactivate(user_id):
    session = get_session()
    try:
        user = session.query(AttendanceUser).filter_by(id=user_id).first()
        if not user:
            abort(404)
        if user.username == current_user.username:
            flash("O'zingizni faolsizlantira olmaysiz", "error")
            return redirect(url_for("users"))
        user.is_active = False
        session.commit()
        log_action(current_user.username, current_user.role, "user_deactivate",
                    target_type="user", target_id=user_id, ip_address=request.remote_addr)
        flash(f"Foydalanuvchi faolsizlantirildi: {user.username}", "success")
    finally:
        session.close()
    return redirect(url_for("users"))


@app.route("/users/<int:user_id>/activate", methods=["POST"])
@super_admin_only
def user_activate(user_id):
    session = get_session()
    try:
        user = session.query(AttendanceUser).filter_by(id=user_id).first()
        if not user:
            abort(404)
        user.is_active = True
        session.commit()
        log_action(current_user.username, current_user.role, "user_activate",
                    target_type="user", target_id=user_id, ip_address=request.remote_addr)
        flash(f"Foydalanuvchi faollashtirildi: {user.username}", "success")
    finally:
        session.close()
    return redirect(url_for("users"))


@app.route("/audit")
@super_admin_only
def audit():
    session = get_session()
    try:
        rows = session.query(AttendanceAuditLog).order_by(AttendanceAuditLog.timestamp.desc()).limit(300).all()
    finally:
        session.close()
    return render_template("audit.html", rows=rows)


@app.template_filter("local_dt")
def local_dt_filter(dt, fmt="%Y-%m-%d %H:%M:%S", fallback="-"):
    if dt is None:
        return fallback
    from config.settings import TIMEZONE_OFFSET_HOURS
    local = dt + timedelta(hours=TIMEZONE_OFFSET_HOURS)
    return local.strftime(fmt)


if __name__ == "__main__":
    port = int(os.getenv("ATTENDANCE_DASHBOARD_PORT", "8090"))
    app.run(host="0.0.0.0", port=port)
