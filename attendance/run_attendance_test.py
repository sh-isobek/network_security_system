"""
Davomat subtizimi uchun TO'LIQ, REAL test to'plami - `run_full_test.py`
bilan bir xil pattern (`check(name, fn)`, ✅/❌, oxirida yakuniy hisobot).

Bu MUSTAQIL fayl (asosiy `run_full_test.py`ga QO'SHILMAGAN) - chunki
Davomat (HR) subtizimi tarmoq xavfsizligi domenidan butunlay mustaqil,
va asosiy test to'plamini keraksiz shishirmaslik uchun ALOHIDA
saqlanadi. Lekin loyihaning asosiy qoidasiga to'liq amal qiladi: HECH
NARSA "ishlashi kerak" deb qoldirilmaydi - har bir qism REAL HTTP/DB
bilan sinaladi.

MUHIM, HALOL CHEKLOV: haqiqiy Hikvision DS-K1T342MFWX terminaliga
(194.93.24.92:88) bu sandbox'dan tarmoq ulanishi YO'Q (tekshirilgan -
`curl` 8 soniyada timeout berdi). Shuning uchun `hikvision_client.py`
LOKAL, soxta ISAPI serveri (rasmiy Hikvision hujjatlaridagi JSON
formatini, jumladan HAQIQIY HTTP Digest Auth oqimini, sahifalab olishni
va noto'g'ri parolni rad etishni to'liq takrorlaydigan) orqali test
qilinadi. Haqiqiy qurilmaga qarshi bir martalik tasdiqlash foydalanuvchi
tarmog'idan turib qilinishi kerak (`docs_ATTENDANCE_SETUP.md`ga qarang).

Ishga tushirish:
    cd network_security_system
    python3 -m attendance.run_attendance_test                 # SQLite
    export DATABASE_URL="postgresql://postgres:testpass123@localhost:5432/attendance_test"
    python3 -m attendance.run_attendance_test                 # PostgreSQL
"""
import hashlib
import json
import os
import sys
import threading
import time
import traceback
from datetime import date, datetime, timedelta, time as time_cls

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ.setdefault("ATTENDANCE_DASHBOARD_SECRET_KEY", "ci-test-attendance-secret")
os.environ.setdefault("SESSION_COOKIE_SECURE", "false")

RESULTS = []


def check(name, fn):
    try:
        fn()
        RESULTS.append((name, True, None))
        print(f"✅ {name}")
    except Exception as e:
        RESULTS.append((name, False, f"{type(e).__name__}: {e}"))
        print(f"❌ {name}: {type(e).__name__}: {e}")
        traceback.print_exc()


def _dash_client(flask_app):
    """`run_full_test.py::_dash_client()` bilan bir xil - CSRF tokenini avtomatik qo'shadi."""
    client = flask_app.test_client()
    orig_post = client.post

    def _post_with_csrf(*args, **kwargs):
        with client.session_transaction() as sess:
            token = sess.get("csrf_token")
        if not token:
            client.get("/")
            with client.session_transaction() as sess:
                token = sess.get("csrf_token")
        if not token:
            client.get("/login")
            with client.session_transaction() as sess:
                token = sess.get("csrf_token")
        if token and kwargs.get("json") is None:
            data = kwargs.get("data")
            data = dict(data) if isinstance(data, dict) else {}
            data.setdefault("csrf_token", token)
            kwargs["data"] = data
        return orig_post(*args, **kwargs)

    client.post = _post_with_csrf
    return client


# ---------------------------------------------------------------------------
print("\n=== 0) BAZANI TAYYORLASH ===")

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./logs/attendance_test.db")
os.environ["DATABASE_URL"] = DATABASE_URL
print(f"DATABASE_URL = {DATABASE_URL}")

if DATABASE_URL.startswith("sqlite:///"):
    db_path = DATABASE_URL.replace("sqlite:///", "", 1)
    if os.path.exists(db_path):
        os.remove(db_path)
        print(f"Eski SQLite fayli o'chirildi: {db_path}")
else:
    # PostgreSQL: attn_* jadvallarini tozalab boshlaymiz (boshqa domenning
    # jadvallariga tegmaymiz - faqat shu subtizimning o'z jadvallari).
    from sqlalchemy import create_engine, text
    eng = create_engine(DATABASE_URL)
    with eng.begin() as conn:
        conn.execute(text("""
            DO $$ DECLARE r RECORD;
            BEGIN
                FOR r IN (SELECT tablename FROM pg_tables WHERE tablename LIKE 'attn_%') LOOP
                    EXECUTE 'DROP TABLE IF EXISTS ' || quote_ident(r.tablename) || ' CASCADE';
                END LOOP;
            END $$;
        """))
    print("Eski attn_* jadvallar tozalandi (PostgreSQL)")

from attendance.database import get_session  # noqa: E402
from attendance.models import (  # noqa: E402
    Employee, AttendanceEvent, WorkSchedule, DailyAttendance, AttendanceUser,
    AttendanceAuditLog, Penalty, DailyReportLog, SyncState,
    ROLE_SUPER_ADMIN, ROLE_HR_ADMIN, ROLE_VIEWER,
    ARRIVAL_EARLY, ARRIVAL_ON_TIME, ARRIVAL_LATE, ARRIVAL_ABSENT,
    DEPARTURE_ON_TIME, DEPARTURE_EARLY, DEPARTURE_LATE,
)
from attendance import calculator, stats as stats_mod, sync_engine, report_engine
from attendance.hikvision_client import HikvisionClient, HikvisionAuthError


# ===========================================================================
print("\n=== 1) LOKAL, SOXTA HIKVISION ISAPI SERVERI (haqiqiy HTTP Digest Auth) ===")

MOCK_USERNAME = "admin"
MOCK_PASSWORD = "Test12345!"
MOCK_REALM = "ISAPI"
MOCK_PORT = 18099

# Xodim 1001: 09:07 da kelib, 18:20 da ketgan (kechikkan, vaqtidan keyin ketgan)
# Xodim 1002: 08:50 da kelib, 17:40 da ketgan (erta kelgan, erta ketgan)
# Xodim 1003: faqat bitta marta, 09:00 da (chegara holat)
def _build_mock_events():
    events = []
    serial = 1000
    base_day = date.today() - timedelta(days=1)  # "kecha" - hisobot shu kun uchun hisoblanadi

    def add(emp_no, hh, mm, ss=0):
        nonlocal serial
        serial += 1
        local_dt = datetime.combine(base_day, time_cls(hh, mm, ss))
        # Test muhitida TIMEZONE_OFFSET_HOURS standart 5 - shuning uchun
        # ISAPI vaqti +05:00 offset bilan yuboriladi (haqiqiy qurilma ham
        # o'z mahalliy vaqtini offset bilan qaytaradi).
        events.append({
            "major": 5, "minor": 75,
            "time": local_dt.strftime("%Y-%m-%dT%H:%M:%S") + "+05:00",
            "employeeNoString": emp_no,
            "name": f"Test Xodim {emp_no}",
            "serialNo": serial,
            "currentVerifyMode": "face",
            "pictureURL": "",
        })

    add("1001", 9, 7)
    add("1001", 18, 20)
    add("1002", 8, 50)
    add("1002", 17, 40)
    add("1003", 9, 0, 0)
    # Ko'p sahifali javobni sinash uchun 40 ta qo'shimcha (boshqa xodim, boshqa kun - filtrlanmaydi)
    for i in range(40):
        add(f"9{i:03d}", 10, 0, i)
    return events


MOCK_EVENTS = _build_mock_events()


def _digest_ha1():
    return hashlib.md5(f"{MOCK_USERNAME}:{MOCK_REALM}:{MOCK_PASSWORD}".encode()).hexdigest()


def _parse_digest_header(header_value: str) -> dict:
    parts = {}
    for item in header_value[len("Digest "):].split(","):
        if "=" not in item:
            continue
        k, v = item.strip().split("=", 1)
        parts[k.strip()] = v.strip().strip('"')
    return parts


def _make_mock_app():
    from flask import Flask, request, jsonify, Response

    app = Flask("mock_hikvision")
    app._nonce = "test-nonce-fixed"  # oddiylik uchun statik (haqiqiy qurilma tasodifiy generatsiya qiladi)

    def _check_auth():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Digest "):
            return False
        d = _parse_digest_header(auth_header)
        if d.get("username") != MOCK_USERNAME:
            return False
        ha1 = _digest_ha1()
        ha2 = hashlib.md5(f"{request.method}:{d.get('uri', request.path + ('?' + request.query_string.decode() if request.query_string else ''))}".encode()).hexdigest()
        expected = hashlib.md5(
            f"{ha1}:{d.get('nonce')}:{d.get('nc')}:{d.get('cnonce')}:{d.get('qop')}:{ha2}".encode()
        ).hexdigest()
        return d.get("response") == expected

    def _unauthorized():
        resp = Response(status=401)
        resp.headers["WWW-Authenticate"] = (
            f'Digest realm="{MOCK_REALM}", qop="auth", nonce="{app._nonce}", opaque="test-opaque"'
        )
        return resp

    @app.route("/ISAPI/System/deviceInfo", methods=["GET"])
    def device_info():
        if not _check_auth():
            return _unauthorized()
        return jsonify({"DeviceInfo": {
            "deviceName": "Test Face Terminal", "model": "DS-K1T342MFWX",
            "serialNumber": "TESTSERIAL001", "firmwareVersion": "V2.0.0",
        }})

    @app.route("/ISAPI/AccessControl/AcsEvent", methods=["POST"])
    def acs_event():
        if not _check_auth():
            return _unauthorized()
        body = request.get_json(force=True)
        cond = body.get("AcsEventCond", {})
        position = int(cond.get("searchResultPosition", 0))
        max_results = int(cond.get("maxResults", 30))
        start_time = datetime.fromisoformat(cond["startTime"])
        end_time = datetime.fromisoformat(cond["endTime"])

        matched = []
        for ev in MOCK_EVENTS:
            ev_time = datetime.fromisoformat(ev["time"])
            if start_time <= ev_time < end_time:
                matched.append(ev)

        page = matched[position:position + max_results]
        more = (position + max_results) < len(matched)
        return jsonify({"AcsEvent": {
            "searchID": cond.get("searchID"),
            "responseStatusStrg": "MORE" if more else "OK",
            "numOfMatches": len(page),
            "totalMatches": len(matched),
            "InfoList": page,
        }})

    return app


def _run_mock_server():
    app = _make_mock_app()
    app.run(host="127.0.0.1", port=MOCK_PORT, debug=False, use_reloader=False)


_mock_thread = threading.Thread(target=_run_mock_server, daemon=True)
_mock_thread.start()
time.sleep(1.0)


def test_hikvision_device_info():
    client = HikvisionClient("127.0.0.1", MOCK_PORT, MOCK_USERNAME, MOCK_PASSWORD)
    info = client.get_device_info()
    assert info["model"] == "DS-K1T342MFWX", info


def test_hikvision_wrong_password_rejected():
    client = HikvisionClient("127.0.0.1", MOCK_PORT, MOCK_USERNAME, "wrong-password")
    try:
        client.get_device_info()
        raise AssertionError("Noto'g'ri parol qabul qilinmasligi kerak edi")
    except HikvisionAuthError:
        pass


def test_hikvision_acs_event_search_and_pagination():
    client = HikvisionClient("127.0.0.1", MOCK_PORT, MOCK_USERNAME, MOCK_PASSWORD)
    base_day = date.today() - timedelta(days=1)
    start = datetime.combine(base_day, time_cls(0, 0)) - timedelta(hours=5)
    end = start + timedelta(days=1)
    events = list(client.search_acs_events(start, end))
    # 5 ta asosiy + 40 ta qo'shimcha = 45 ta, MAX_RESULTS_PER_PAGE=30 bo'lgani
    # uchun bu KAMIDA 2 sahifani talab qiladi - pagination ishlaganini isbotlaydi.
    assert len(events) == 45, f"Kutilgan 45, olindi {len(events)}"
    employee_nos = {e["employeeNoString"] for e in events}
    assert "1001" in employee_nos and "1002" in employee_nos and "1003" in employee_nos


check("Hikvision mijozi: deviceInfo (real Digest Auth)", test_hikvision_device_info)
check("Hikvision mijozi: noto'g'ri parol RAD ETILADI", test_hikvision_wrong_password_rejected)
check("Hikvision mijozi: AcsEvent qidiruv + sahifalash (45 ta hodisa, 2+ sahifa)",
      test_hikvision_acs_event_search_and_pagination)


# ===========================================================================
print("\n=== 2) SYNC ENGINE: qurilmadan DB'ga ===")

os.environ["HIKVISION_HOST"] = "127.0.0.1"
os.environ["HIKVISION_PORT"] = str(MOCK_PORT)
os.environ["HIKVISION_USERNAME"] = MOCK_USERNAME
os.environ["HIKVISION_PASSWORD"] = MOCK_PASSWORD


def test_sync_engine_first_run():
    n = sync_engine.run_once(since_hours=48)
    assert n == 45, f"Kutilgan 45 ta yangi hodisa, olindi {n}"

    session = get_session()
    try:
        total = session.query(AttendanceEvent).count()
        assert total == 45, total
        emp = session.query(Employee).filter_by(employee_no="1001").first()
        assert emp is not None, "Xodim avtomatik yaratilmadi"
        assert emp.full_name.startswith("Xodim #"), emp.full_name
    finally:
        session.close()


def test_sync_engine_dedup_on_second_run():
    n = sync_engine.run_once(since_hours=48)
    assert n == 0, f"Ikkinchi chaqiruv dublikat qo'shmasligi kerak edi, lekin {n} ta qo'shdi"

    session = get_session()
    try:
        total = session.query(AttendanceEvent).count()
        assert total == 45, f"Dublikat paydo bo'ldi: {total}"
    finally:
        session.close()


check("Sync engine: birinchi ishga tushirish (45 ta hodisa + xodimlar avtomatik yaratildi)",
      test_sync_engine_first_run)
check("Sync engine: qayta chaqirilganda DUBLIKAT yaratilmaydi (device_event_id unique)",
      test_sync_engine_dedup_on_second_run)


# ===========================================================================
print("\n=== 3) KALKULYATOR: kechikish/erta kelish/erta ketish/kelmaslik ===")


def _set_real_names():
    """Test o'qilishini osonlashtirish uchun avtomatik yaratilgan xodimlarga ism beramiz."""
    session = get_session()
    try:
        names = {"1001": "Aliyev Vali", "1002": "Karimova Nodira", "1003": "Rustamov Sardor"}
        for no, name in names.items():
            emp = session.query(Employee).filter_by(employee_no=no).first()
            if emp:
                emp.full_name = name
        session.commit()
    finally:
        session.close()


_set_real_names()

TEST_WORK_DATE = date.today() - timedelta(days=1)


def test_calculator_late_arrival_and_late_departure():
    """1001: 09:07 kelgan (standart 09:00+5 daqiqa grace -> 09:05 dan keyin = kech),
    18:20 ketgan (standart 18:00+-5 daqiqa oynasidan tashqarida, keyin = kech ketdi)."""
    session = get_session()
    try:
        emp = session.query(Employee).filter_by(employee_no="1001").first()
        rec = calculator.compute_employee_day(session, emp, TEST_WORK_DATE)
        session.commit()
        assert rec.arrival_status == ARRIVAL_LATE, rec.arrival_status
        assert rec.late_minutes == 2, rec.late_minutes  # 09:07 - 09:05(grace) = 2 daqiqa
        assert rec.departure_status == DEPARTURE_LATE, rec.departure_status
    finally:
        session.close()


def test_calculator_early_arrival_and_early_departure():
    """1002: 08:50 kelgan (09:00 dan oldin -> erta keldi), 17:40 ketgan (18:00-5=17:55 dan oldin -> erta ketdi)."""
    session = get_session()
    try:
        emp = session.query(Employee).filter_by(employee_no="1002").first()
        rec = calculator.compute_employee_day(session, emp, TEST_WORK_DATE)
        session.commit()
        assert rec.arrival_status == ARRIVAL_EARLY, rec.arrival_status
        assert rec.departure_status == DEPARTURE_EARLY, rec.departure_status
        assert rec.early_leave_minutes == 15, rec.early_leave_minutes  # 17:55 - 17:40
    finally:
        session.close()


def test_calculator_absent_employee():
    """Hech qanday hodisasi bo'lmagan (lekin faol) xodim uchun 'kelmadi' bo'lishi kerak."""
    session = get_session()
    try:
        emp = Employee(employee_no="ABSENT1", full_name="Kelmagan Xodim", is_active=True)
        session.add(emp)
        session.flush()
        rec = calculator.compute_employee_day(session, emp, TEST_WORK_DATE)
        session.commit()
        assert rec.arrival_status == ARRIVAL_ABSENT, rec.arrival_status
        assert rec.first_seen is None
    finally:
        session.close()


def test_calculator_run_once_computes_all_active_employees():
    n = calculator.run_once(TEST_WORK_DATE)
    assert n >= 3, n
    session = get_session()
    try:
        count = session.query(DailyAttendance).filter_by(work_date=TEST_WORK_DATE).count()
        assert count >= 3, count
    finally:
        session.close()


check("Kalkulyator: kechikish + kech ketish (1001)", test_calculator_late_arrival_and_late_departure)
check("Kalkulyator: erta kelish + erta ketish (1002)", test_calculator_early_arrival_and_early_departure)
check("Kalkulyator: hodisasiz xodim = 'kelmadi'", test_calculator_absent_employee)
check("Kalkulyator: run_once() barcha faol xodimlarni hisoblaydi", test_calculator_run_once_computes_all_active_employees)


# ===========================================================================
print("\n=== 4) STATISTIKA (Dashboard grafiklar uchun) ===")


def test_stats_percentages():
    session = get_session()
    try:
        result = stats_mod.compute_period_stats(session, TEST_WORK_DATE, TEST_WORK_DATE)
        assert result["total_records"] >= 3
        total_pct = (result["arrival"]["erta_keldi"]["pct"] + result["arrival"]["vaqtida"]["pct"] +
                     result["arrival"]["kechikdi"]["pct"] + result["arrival"]["kelmadi"]["pct"])
        assert 99.0 <= total_pct <= 101.0, f"Foizlar 100%ga yaqin bo'lishi kerak, oldik: {total_pct}"
    finally:
        session.close()


check("Statistika: kelish % taqsimoti 100%ga yig'iladi", test_stats_percentages)


# ===========================================================================
print("\n=== 5) KUNLIK HISOBOT (Telegram + Email, real yuborish MOCK bilan) ===")

_telegram_calls = []
_email_calls = []


def _fake_telegram_post(url, json=None, timeout=None, **kwargs):
    _telegram_calls.append((url, json))
    class _Resp:
        status_code = 200
        text = "ok"
    return _Resp()


class _FakeSMTP:
    def __init__(self, host, port, timeout=None):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def starttls(self):
        pass

    def login(self, u, p):
        pass

    def sendmail(self, from_addr, to_addrs, msg):
        _email_calls.append((from_addr, to_addrs, msg))


def test_report_text_contains_late_and_absent():
    session = get_session()
    try:
        text = report_engine.build_report_text(session, TEST_WORK_DATE)
        assert "Aliyev Vali" in text, text
        assert "Kelmagan Xodim" in text, text
    finally:
        session.close()


def test_send_daily_report_telegram_and_email_and_idempotent():
    os.environ["ATTENDANCE_TELEGRAM_BOT_TOKEN"] = "test-token"
    os.environ["ATTENDANCE_TELEGRAM_CHAT_ID"] = "12345"
    os.environ["ATTENDANCE_REPORT_EMAILS"] = "hr@example.com"

    orig_post = report_engine.requests.post
    orig_smtp = report_engine.smtplib.SMTP
    report_engine.requests.post = _fake_telegram_post
    report_engine.smtplib.SMTP = _FakeSMTP
    try:
        result = report_engine.send_daily_report(TEST_WORK_DATE)
        assert result["telegram_sent"] is True, result
        assert result["email_sent"] is True, result
        assert len(_telegram_calls) == 1
        assert len(_email_calls) == 1

        # Ikkinchi chaqiruv - takroriy yuborilmasligi kerak (DailyReportLog orqali)
        result2 = report_engine.send_daily_report(TEST_WORK_DATE)
        assert result2.get("skipped") is True, result2
        assert len(_telegram_calls) == 1, "Takroriy Telegram xabari yuborilmasligi kerak edi"
        assert len(_email_calls) == 1, "Takroriy email yuborilmasligi kerak edi"
    finally:
        report_engine.requests.post = orig_post
        report_engine.smtplib.SMTP = orig_smtp


check("Hisobot matni: kechikkan/kelmagan xodimlar ro'yxatda", test_report_text_contains_late_and_absent)
check("Kunlik hisobot: Telegram+Email yuboriladi VA takroriy yuborilmaydi (idempotent)",
      test_send_daily_report_telegram_and_email_and_idempotent)


# ===========================================================================
print("\n=== 6) RBAC DASHBOARD (real HTTP, 3 rol) ===")

from attendance.dashboard.app import app as dash_flask_app  # noqa: E402
from werkzeug.security import generate_password_hash  # noqa: E402

dash_flask_app.config["TESTING"] = True


def _create_dashboard_users():
    session = get_session()
    try:
        for username, role in [("super1", ROLE_SUPER_ADMIN), ("hr1", ROLE_HR_ADMIN), ("view1", ROLE_VIEWER)]:
            if not session.query(AttendanceUser).filter_by(username=username).first():
                session.add(AttendanceUser(
                    username=username, password_hash=generate_password_hash("Passw0rd!"),
                    role=role, is_active=True,
                ))
        session.commit()
    finally:
        session.close()


_create_dashboard_users()


def _login(client, username, password="Passw0rd!"):
    resp = client.post("/login", data={"username": username, "password": password}, follow_redirects=True)
    assert resp.status_code == 200, resp.status_code
    return resp


def test_viewer_sees_only_charts():
    client = _dash_client(dash_flask_app)
    _login(client, "view1")
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Kelish holati" in resp.data
    # Viewer xodimlar/foydalanuvchilar/audit sahifalariga kira OLMASLIGI kerak
    for path in ("/employees", "/reports", "/penalties", "/users", "/audit"):
        r = client.get(path)
        assert r.status_code == 403, f"{path} viewer uchun 403 bo'lishi kerak edi, oldi {r.status_code}"


def test_hr_admin_cannot_add_or_delete_employee():
    client = _dash_client(dash_flask_app)
    _login(client, "hr1")

    r = client.get("/employees")
    assert r.status_code == 200

    session = get_session()
    try:
        before_count = session.query(Employee).count()
    finally:
        session.close()

    r_add = client.post("/employees/add", data={
        "employee_no": "HRTEST1", "full_name": "HR Qo'sha Olmaydi",
    }, follow_redirects=False)
    assert r_add.status_code == 403, f"hr_admin xodim QO'SHA OLMASLIGI kerak, oldi {r_add.status_code}"

    session = get_session()
    try:
        emp = session.query(Employee).filter_by(employee_no="1002").first()
        assert emp is not None
        emp_id = emp.id
    finally:
        session.close()

    r_del = client.post(f"/employees/{emp_id}/delete", data={}, follow_redirects=False)
    assert r_del.status_code == 403, f"hr_admin xodim O'CHIRA OLMASLIGI kerak, oldi {r_del.status_code}"

    session = get_session()
    try:
        after_count = session.query(Employee).count()
        assert after_count == before_count, "hr_admin amali xodimlar sonini o'zgartirib yubordi!"
    finally:
        session.close()


def test_hr_admin_can_edit_employee_and_view_reports_and_add_penalty():
    client = _dash_client(dash_flask_app)
    _login(client, "hr1")

    session = get_session()
    try:
        emp = session.query(Employee).filter_by(employee_no="1002").first()
        emp_id = emp.id
    finally:
        session.close()

    r_edit = client.post(f"/employees/{emp_id}/edit", data={
        "full_name": "Karimova Nodira Yangilangan", "department": "Buxgalteriya",
        "position": "Kassir", "is_active": "on",
    })
    assert r_edit.status_code in (200, 302), r_edit.status_code

    session = get_session()
    try:
        emp = session.query(Employee).filter_by(id=emp_id).first()
        assert emp.full_name == "Karimova Nodira Yangilangan", emp.full_name
        assert emp.department == "Buxgalteriya", emp.department
    finally:
        session.close()

    r_reports = client.get("/reports?period=month")
    assert r_reports.status_code == 200

    r_penalty = client.post("/penalties/add", data={
        "employee_id": str(emp_id), "penalty_type": "ogohlantirish", "reason": "Test uchun kechikish",
    })
    assert r_penalty.status_code in (200, 302), r_penalty.status_code

    session = get_session()
    try:
        p = session.query(Penalty).filter_by(employee_id=emp_id).first()
        assert p is not None, "Ogohlantirish yozuvi yaratilmadi"
        assert p.penalty_type == "ogohlantirish"
    finally:
        session.close()


def test_super_admin_can_add_and_delete_employee_and_manage_users():
    client = _dash_client(dash_flask_app)
    _login(client, "super1")

    session = get_session()
    try:
        before_count = session.query(Employee).count()
    finally:
        session.close()

    r_add = client.post("/employees/add", data={
        "employee_no": "SATEST1", "full_name": "Super Admin Qo'shdi", "department": "IT",
    })
    assert r_add.status_code in (200, 302), r_add.status_code

    session = get_session()
    try:
        emp = session.query(Employee).filter_by(employee_no="SATEST1").first()
        assert emp is not None, "super_admin xodim qo'sha olishi kerak edi"
        emp_id = emp.id
        after_add_count = session.query(Employee).count()
        assert after_add_count == before_count + 1
    finally:
        session.close()

    r_del = client.post(f"/employees/{emp_id}/delete", data={})
    assert r_del.status_code in (200, 302), r_del.status_code

    session = get_session()
    try:
        assert session.query(Employee).filter_by(id=emp_id).first() is None
        final_count = session.query(Employee).count()
        assert final_count == before_count
    finally:
        session.close()

    r_users = client.get("/users")
    assert r_users.status_code == 200

    r_user_add = client.post("/users/add", data={"username": "newview", "password": "Passw0rd!", "role": ROLE_VIEWER})
    assert r_user_add.status_code in (200, 302), r_user_add.status_code

    session = get_session()
    try:
        assert session.query(AttendanceUser).filter_by(username="newview").first() is not None
    finally:
        session.close()


def test_audit_log_records_role_actions_and_only_super_admin_sees_it():
    client_hr = _dash_client(dash_flask_app)
    _login(client_hr, "hr1")
    r = client_hr.get("/audit")
    assert r.status_code == 403, "hr_admin Audit Log'ni ko'ra OLMASLIGI kerak"

    client_super = _dash_client(dash_flask_app)
    _login(client_super, "super1")
    r = client_super.get("/audit")
    assert r.status_code == 200

    session = get_session()
    try:
        actions = {row.action for row in session.query(AttendanceAuditLog).all()}
        assert "employee_edit" in actions, actions  # hr1 tahrirlagan edi
        assert "penalty_add" in actions, actions
        assert "employee_add" in actions, actions   # super1 qo'shgan edi
        assert "employee_delete" in actions, actions
        # hr_admin'ning muvaffaqiyatsiz (403) urinishlari Flask abort() darajasida
        # to'xtatilgani uchun audit'ga yozilmaydi - bu RBAC HAQIQATAN nazorat
        # qatlamida (route ichida emas) ishlayotganini tasdiqlaydi.
    finally:
        session.close()


check("RBAC: viewer FAQAT grafiklarni ko'radi (boshqa sahifalar 403)", test_viewer_sees_only_charts)
check("RBAC: hr_admin xodim QO'SHA/O'CHIRA OLMAYDI (403, DB o'zgarmaydi)",
      test_hr_admin_cannot_add_or_delete_employee)
check("RBAC: hr_admin tahrirlashi/hisobot/ogohlantirish MUMKIN", test_hr_admin_can_edit_employee_and_view_reports_and_add_penalty)
check("RBAC: super_admin xodim qo'sha/o'chira OLADI + foydalanuvchi boshqaradi",
      test_super_admin_can_add_and_delete_employee_and_manage_users)
check("RBAC: Audit Log rollar amalini qayd etadi, FAQAT super_admin ko'radi",
      test_audit_log_records_role_actions_and_only_super_admin_sees_it)


# ===========================================================================
print("\n=== YAKUNIY HISOBOT ===")
passed = sum(1 for _, ok, _ in RESULTS if ok)
total = len(RESULTS)
for name, ok, err in RESULTS:
    if not ok:
        print(f"  ❌ {name}: {err}")
print(f"\n{passed}/{total} test o'tdi")
if passed == total:
    print("✅ BARCHA TESTLAR MUVAFFAQIYATLI O'TDI")
else:
    print("❌ BA'ZI TESTLAR MUVAFFAQIYATSIZ")
    sys.exit(1)
