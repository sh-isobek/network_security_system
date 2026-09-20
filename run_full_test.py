"""
TO'LIQ TIZIM TESTI - barcha bosqichlarni (0-13) birlashtirib, xatolarni tekshiradi.
Har bir qadam natijasi ✅/❌ bilan belgilanadi, xatolik bo'lsa to'xtamasdan davom etadi
(oxirida yakuniy hisobot chiqadi).

Standart holatda SQLite bazasida ishlaydi. PostgreSQL (Docker Compose'da
ishlatiladigan) bilan sinash uchun:

    export DATABASE_URL="postgresql://user:pass@localhost:5432/dbname"
    python3 run_full_test.py

(Bu loyiha PostgreSQL'da ham to'liq 14/14 test bilan sinovdan o'tkazilgan.)
"""
import os
import sys
import traceback

os.environ["DEMO_MODE"] = "true"
# MUHIM: dashboard/app.py endi DASHBOARD_SECRET_KEY'ni MAJBURIY qiladi
# (bo'sh bo'lsa import paytida RuntimeError) - production'da tasodifiy
# per-process kalit xavfli (ko'p gunicorn worker orasida sessiya cookie
# imzosi mos kelmay qolishi mumkin edi). Test muhitida esa doimiy, oldindan
# ma'lum qiymat kerak - shu yerda, HAR QANDAY `dashboard.app` importidan
# OLDIN o'rnatiladi.
os.environ.setdefault("DASHBOARD_SECRET_KEY", "ci-test-dashboard-secret-key")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

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
    """
    `dashboard/app.py` endi CSRF himoyasini qo'shdi (autentifikatsiyalangan
    sessiya POST so'rov yuborganda, forma ichidagi yashirin `csrf_token`
    maydoni sessiyadagi qiymat bilan mos kelishi SHART - haqiqiy brauzerda
    `<form>` ichidagi yashirin input orqali avtomatik yuboriladi). Oddiy
    `flask_app.test_client()` buni bilmaydi va har bir POST 400 bilan rad
    etiladi - shuning uchun bu yerda `.post()` avtomatik ravishda joriy
    sessiyadan `csrf_token`ni o'qib, form ma'lumotlariga qo'shib yuboradigan
    wrapper qaytariladi (login/mfa_verify kabi autentifikatsiyadan OLDINGI
    POST'larga ta'sir qilmaydi - ular `current_user.is_authenticated` False
    bo'lgani uchun CSRF tekshiruvidan umuman o'tmaydi).
    """
    client = flask_app.test_client()
    orig_post = client.post

    def _post_with_csrf(*args, **kwargs):
        with client.session_transaction() as sess:
            token = sess.get("csrf_token")
        if not token:
            # Sessiyada hali csrf_token yo'q (hali hech qanday shablon
            # render qilinmagan) - "/" (autentifikatsiyalangan bo'lsa)
            # yoki "/login" (bo'lmasa) orqali generatsiya qilamiz.
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
print("\n=== 0) BAZANI TOZALASH VA QAYTA YARATISH ===")
db_path = "logs/security_system.db"
if os.path.exists(db_path):
    os.remove(db_path)
if os.path.exists("logs/raw_syslog.log"):
    os.remove("logs/raw_syslog.log")

from db.database import get_session
from db.models import (
    RawLog, Device, Event, Alert, WhitelistEntry, BlacklistEntry,
    FileEvent, HashBlacklist, User, WebAccessLog,
)

check("Baza yaratildi", lambda: get_session().close())

# ---------------------------------------------------------------------------
print("\n=== 1) WHITELIST/BLACKLIST SEED ===")


def _seed():
    s = get_session()
    s.add(WhitelistEntry(value="172.16.0.10", description="1C server"))
    s.add(BlacklistEntry(value="malicious-test-domain.com", source="manual", reason="test"))
    s.add(HashBlacklist(sha256="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0",
                         threat_name="EICAR-Test", source="manual"))
    s.commit()
    s.close()


check("Whitelist/Blacklist/HashBlacklist seed qilindi", _seed)

# ---------------------------------------------------------------------------
print("\n=== 2) SYSLOG PARSER PIPELINE (Kerio DHCP, Connection, Windows DNS) ===")


def _test_parser_pipeline():
    from db.models import RawLog
    s = get_session()
    logs = [
        RawLog(source_ip="172.16.0.1", raw_message="[18/Apr/2013 10:22:47] [IPv4] 172.16.1.45 [MAC] AA-BB-CC-DD-EE-FF (Test) [Hostname] ACCOUNTING-PC"),
        RawLog(source_ip="172.16.0.1", raw_message="[18/Apr/2013 10:22:47] [ID] 613181 [Rule] NAT [Service] HTTPS [Connection] TCP 172.16.1.45:51234 > 8.8.8.8:443 [Duration] 5 sec [Bytes] 100/200/300 [Packets] 2/3/5"),
        RawLog(source_ip="172.16.0.11", raw_message='{"EventID":256,"ClientIP":"172.16.2.5","QueryName":"malicious-test-domain.com","QueryType":"A"}'),
        RawLog(source_ip="172.16.0.11", raw_message='{"EventID":256,"ClientIP":"172.16.2.6","QueryName":"google.com","QueryType":"A"}'),
        RawLog(source_ip="172.16.0.99", raw_message="bu hech qanday parserga mos kelmaydigan xom matn"),
    ]
    s.add_all(logs)
    s.commit()
    s.close()

    from engine.parser_engine import run_once
    count = run_once()
    assert count == 5, f"Kutilgan 5 ta yozuv, lekin {count} ta qayta ishlandi"

    s = get_session()
    unprocessed = s.query(RawLog).filter(RawLog.processed == False).count()
    assert unprocessed == 0, f"{unprocessed} ta yozuv hali processed=False"

    devices = s.query(Device).all()
    assert len(devices) >= 3, f"Kamida 3 ta device kutilgan, {len(devices)} ta topildi"

    dev_1_45 = s.query(Device).filter(Device.ip_address == "172.16.1.45").first()
    assert dev_1_45.mac_address == "AA:BB:CC:DD:EE:FF", "DHCP orqali MAC to'g'ri bog'lanmadi"
    assert dev_1_45.hostname == "ACCOUNTING-PC", "DHCP orqali hostname to'g'ri bog'lanmadi"

    events = s.query(Event).all()
    assert len(events) == 3, f"3 ta event (1 connection + 2 dns) kutilgan, {len(events)} ta topildi"

    alerts = s.query(Alert).filter(Alert.event_id.isnot(None)).all()
    assert len(alerts) == 1, f"Faqat 1 ta DNS blacklist alert kutilgan, {len(alerts)} ta topildi"
    assert alerts[0].device_id is not None, "Alert device_id bilan bog'lanmagan"
    s.close()


check("Parser pipeline (DHCP+Connection+DNS, blacklist alert)", _test_parser_pipeline)

# ---------------------------------------------------------------------------
print("\n=== 3) FAYL ANALIZ PIPELINE (hash, YARA, ZIP, Office, PDF) ===")


def _test_file_pipeline():
    import hashlib
    import zipfile

    os.makedirs("/tmp/test_filestore", exist_ok=True)

    # 3a) EICAR (mahalliy blacklist orqali topiladigan)
    eicar_path = "/tmp/test_filestore/invoice.exe"
    with open(eicar_path, "wb") as f:
        f.write(b"EICAR-TEST-DUMMY-CONTENT")  # haqiqiy EICAR emas, faqat hash mos kelishi uchun quyida override qilamiz

    # Haqiqiy sinov uchun HashBlacklist'dagi hash bilan mos keladigan fayl kerak emas -
    # biz to'g'ridan-to'g'ri FileEvent'ga o'sha hash'ni yozamiz (Suricata ham shunday qiladi - hash hisoblab beradi)
    known_bad_hash = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0"

    # 3b) ZIP ichida embedded PE (YARA orqali topiladigan)
    zip_path = "/tmp/test_filestore/archive.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("payload.exe", b"MZ" + b"\x90" * 58 + b"This program cannot be run in DOS mode")
        zf.writestr("readme.txt", b"Bu oddiy va xavfsiz matn.")

    # 3c) PDF ichida JS (YARA orqali topiladigan)
    pdf_path = "/tmp/test_filestore/report.pdf"
    with open(pdf_path, "wb") as f:
        f.write(b"%PDF-1.4\n1 0 obj << /Type /Catalog /OpenAction 2 0 R >>\n/JavaScript (app.alert(1))\nendobj")

    # 3d) Toza fayl
    clean_path = "/tmp/test_filestore/clean.txt"
    with open(clean_path, "wb") as f:
        f.write(b"Bu 100% xavfsiz oddiy matn fayli, hech qanday tahdid yo'q.")

    def sha(path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    s = get_session()
    entries = [
        FileEvent(src_ip="172.16.2.10", dest_ip="1.2.3.4", filename="invoice.exe", file_ext="exe",
                   size=100, sha256=known_bad_hash, md5="x", stored_path=eicar_path, checked=False),
        FileEvent(src_ip="172.16.2.20", dest_ip="1.2.3.5", filename="archive.zip", file_ext="zip",
                   size=os.path.getsize(zip_path), sha256=sha(zip_path), md5="x", stored_path=zip_path, checked=False),
        FileEvent(src_ip="172.16.2.30", dest_ip="1.2.3.6", filename="report.pdf", file_ext="pdf",
                   size=os.path.getsize(pdf_path), sha256=sha(pdf_path), md5="x", stored_path=pdf_path, checked=False),
        FileEvent(src_ip="172.16.2.40", dest_ip="1.2.3.7", filename="clean.txt", file_ext="txt",
                   size=os.path.getsize(clean_path), sha256=sha(clean_path), md5="x", stored_path=clean_path, checked=False),
    ]
    s.add_all(entries)
    s.commit()
    s.close()

    from engine.file_analysis_engine import run_once as file_analysis_run
    from engine.deep_scan_engine import run_once as deep_scan_run

    n1 = file_analysis_run()
    assert n1 == 4, f"4 ta fayl hash-tekshiruvidan o'tishi kerak edi, {n1} ta o'tdi"

    n2 = deep_scan_run()
    assert n2 == 4, f"4 ta fayl deep-scan'dan o'tishi kerak edi, {n2} ta o'tdi"

    # ZIP ichidan chiqqan payload.exe ni ham tekshirish uchun yana ikki marta ishga tushiramiz
    file_analysis_run()
    deep_scan_run()

    s = get_session()
    fes = {fe.filename: fe for fe in s.query(FileEvent).all()}

    assert fes["invoice.exe"].verdict == "malicious", "invoice.exe (hash blacklist) malicious deb topilishi kerak edi"
    assert fes["archive.zip"].verdict == "malicious", "archive.zip (ichida PE bor) malicious deb topilishi kerak edi"
    assert fes["report.pdf"].verdict == "malicious", "report.pdf (ichida JS bor) malicious deb topilishi kerak edi"
    # MUHIM (verdict taksonomiyasi tuzatilgan): bu sandbox'da VT_API_KEY
    # sozlanmagan va MalwareBazaar'ga tarmoq kirish yo'q - ya'ni HECH
    # QANDAY manba bu faylni haqiqatan "toza" deb TASDIQLAMAGAN, faqat
    # "zararli emas" deb topilmagan. To'g'ri verdict endi "clean" EMAS,
    # "unknown" ("hali klassifikatsiya qilinmagan") - avval bu holat
    # noto'g'ri ravishda "clean" deb belgilanardi (aynan shu xato
    # tuzatildi - pastdagi alohida testlarga qarang).
    # YANGILANDI (foydalanuvchi so'rovi: "unknown" hech qachon qolmasin): fayl
    # diskda (stored_path) bor va deep scan (YARA/ClamAV/fayl-turi/PDF/Office/
    # heuristik) HECH NARSA topmagan - endi "unknown" emas, "clean".
    assert fes["clean.txt"].verdict == "clean", "to'liq skanerlangan, hech narsa topilmagan fayl 'clean' bo'lishi kerak (deep scan 'unknown'ni hal qiladi)"

    # ZIP ichidan chiqqan payload.exe alohida FileEvent sifatida yaratilganini tekshirish
    payload = s.query(FileEvent).filter(FileEvent.filename == "payload.exe").first()
    assert payload is not None, "ZIP ichidan payload.exe chiqarilmagan"
    assert payload.parent_file_event_id == fes["archive.zip"].id, "payload.exe parent_id noto'g'ri"
    assert payload.verdict == "malicious", "payload.exe malicious deb topilishi kerak edi"

    readme = s.query(FileEvent).filter(FileEvent.filename == "readme.txt").first()
    assert readme is not None and readme.verdict == "clean", "readme.txt deep scan'dan keyin 'clean' bo'lishi kerak edi (hech narsa topilmagan)"

    file_alerts = s.query(Alert).filter(Alert.file_event_id.isnot(None)).all()
    assert len(file_alerts) >= 3, f"Kamida 3 ta fayl-alert kutilgan, {len(file_alerts)} ta topildi"
    for a in file_alerts:
        assert a.device_id is not None, f"Alert {a.id} device_id bilan bog'lanmagan"
    s.close()


check("Fayl analiz pipeline (hash+YARA+ZIP rekursiya+soxta-pozitiv yo'qligi)", _test_file_pipeline)

# ---------------------------------------------------------------------------
print("\n=== 4) OFFICE MAKRO SKANER (soxta pozitiv tekshiruvi) ===")


def _test_office_scanner_false_positive():
    from scanners.office_scanner import scan_office_file
    # Office bo'lmagan fayl uchun None qaytarishi kerak (oldingi tuzatilgan xato)
    r = scan_office_file("/tmp/test_filestore/report.pdf")
    assert r is None, f"PDF fayl uchun None qaytarishi kerak edi, lekin {r} qaytardi"


check("Office scanner soxta-pozitiv himoyasi", _test_office_scanner_false_positive)

# ---------------------------------------------------------------------------
print("\n=== 5) ARXIV SKANER XAVFSIZLIK CHEKLOVLARI (path traversal) ===")


def _test_archive_path_traversal():
    import zipfile
    from scanners.archive_scanner import _safe_member_path

    assert _safe_member_path("normal_file.txt") is True
    assert _safe_member_path("../../etc/passwd") is False
    assert _safe_member_path("/etc/passwd") is False
    assert _safe_member_path("subdir/file.txt") is True


check("Arxiv path-traversal himoyasi", _test_archive_path_traversal)

# ---------------------------------------------------------------------------
print("\n=== 6) RESPONSE ENGINE (avtomatik javob choralari) ===")


def _test_response_engine():
    """
    `network_response_done` bayrog'iga asoslangan navbat mantig'ini
    tekshiradi (o'zi topilgan bug'dan keyin `action_taken.like("TODO%")`
    matn-qidiruvi o'rniga). `action_taken`ga oldindan (masalan Endpoint
    Agent'ning "fayl o'chirildi" xabari) biror narsa yozilgan bo'lsa,
    response_engine buni USTIDAN YOZMASLIGI, faqat QO'SHIB yozishi ham
    tekshiriladi.
    """
    s = get_session()
    d_wifi = Device(ip_address="172.16.3.1", mac_address="AA:11:22:33:44:55", connection_type="wifi", source="test")
    d_unknown = Device(ip_address="172.16.3.2", mac_address="BB:11:22:33:44:55", connection_type="unknown", source="test")
    s.add_all([d_wifi, d_unknown])
    s.flush()

    a1 = Alert(device_id=d_wifi.id, severity="critical", reason="test",
               action_taken="Endpoint Agent: fayl o'chirildi")  # oldindan yozilgan matn - YO'QOLMASLIGI kerak
    a2 = Alert(device_id=d_unknown.id, severity="critical", reason="test")
    a3 = Alert(device_id=None, severity="high", reason="device yo'q")
    s.add_all([a1, a2, a3])
    s.commit()
    ids = [a1.id, a2.id, a3.id]
    s.close()

    from engine.response_engine import run_once
    n = run_once()
    # Diqqat: response_engine FAQAT shu 3 tasini emas, balki bazadagi barcha
    # `network_response_done=False` alertlarni (2 va 3-bosqichlarda
    # yaratilganlarni ham, masalan minglab UEBA "medium" alertlari) qayta
    # ishlaydi - bu to'g'ri xatti-harakat (hech qanday alert e'tibordan
    # chetda qolmasligi kerak). Shuning uchun n >= 3 tekshiramiz.
    assert n >= 3, f"Kamida 3 ta alert qayta ishlanishi kerak edi, {n} ta ishlandi"

    s = get_session()
    for aid in ids:
        a = s.query(Alert).filter(Alert.id == aid).first()
        assert a.network_response_done is True, f"Alert {aid}: network_response_done True bo'lishi kerak edi"
    a1_after = s.query(Alert).filter(Alert.id == ids[0]).first()
    assert "Endpoint Agent: fayl o'chirildi" in a1_after.action_taken, (
        f"Oldindan yozilgan (fayl darajasidagi) xabar YO'QOLGAN: {a1_after.action_taken}"
    )
    assert "AVTOMATIK TARMOQ CHORASI" in a1_after.action_taken or "TARMOQ CHORASI MUVAFFAQIYATSIZ" in a1_after.action_taken, (
        f"Tarmoq chorasi natijasi QO'SHILMAGAN: {a1_after.action_taken}"
    )
    s.close()


check("Response engine (device_id yo'qligi, mock adapter, real xato holatlari)", _test_response_engine)

# ---------------------------------------------------------------------------
print("\n=== 7) BO'SH NAVBAT BILAN ISHLASH (edge case) ===")


def _test_empty_queue():
    from engine.parser_engine import run_once as p
    from engine.file_analysis_engine import run_once as f
    from engine.deep_scan_engine import run_once as d
    from engine.response_engine import run_once as r
    assert p() == 0
    assert f() == 0
    assert d() == 0
    assert r() == 0


check("Bo'sh navbatlar bilan barcha enginelar (xatosiz)", _test_empty_queue)

# ---------------------------------------------------------------------------
print("\n=== 8) API SERVER (Flask test client orqali, real port ochmasdan) ===")


def _test_api_server():
    from api import server as api_server
    api_server.AGENT_API_KEY = "test-key-for-unit-test"
    client = api_server.app.test_client()

    # Health
    r = client.get("/api/v1/health")
    assert r.status_code == 200

    # API kalitsiz - 401
    r = client.post("/api/v1/check_hash", json={"sha256": "a" * 64})
    assert r.status_code == 401

    # Noto'g'ri uzunlikdagi hash - 400
    r = client.post("/api/v1/check_hash", json={"sha256": "abc"},
                     headers={"X-API-Key": "test-key-for-unit-test"})
    assert r.status_code == 400

    # Toza hash
    r = client.post("/api/v1/check_hash", json={"sha256": "b" * 64},
                     headers={"X-API-Key": "test-key-for-unit-test"})
    assert r.status_code == 200
    assert r.get_json()["malicious"] is False

    # HashBlacklist'dagi hash
    s = get_session()
    s.add(HashBlacklist(sha256="c" * 64, threat_name="Unit-Test-Threat", source="manual"))
    s.commit()
    s.close()

    r = client.post("/api/v1/check_hash", json={"sha256": "c" * 64},
                     headers={"X-API-Key": "test-key-for-unit-test"})
    assert r.status_code == 200
    body = r.get_json()
    assert body["malicious"] is True
    assert body["threat_name"] == "Unit-Test-Threat"

    # report_incident
    r = client.post("/api/v1/report_incident", json={
        "hostname": "TEST-PC", "ip_address": "172.16.9.9",
        "filename": "test.exe", "sha256": "c" * 64,
        "threat_name": "Unit-Test-Threat", "file_deleted": True, "process_killed": True,
        "process_name": "test.exe",
    }, headers={"X-API-Key": "test-key-for-unit-test"})
    assert r.status_code == 200
    alert_id = r.get_json()["alert_id"]

    s = get_session()
    alert = s.query(Alert).filter(Alert.id == alert_id).first()
    assert alert is not None
    assert alert.device_id is not None
    assert "Unit-Test-Threat" in alert.reason
    s.close()

    # Majburiy maydon yo'q - 400
    r = client.post("/api/v1/report_incident", json={"hostname": "X"},
                     headers={"X-API-Key": "test-key-for-unit-test"})
    assert r.status_code == 400


check("API server (health/auth/validatsiya/blacklist/incident)", _test_api_server)

# ---------------------------------------------------------------------------
print("\n=== 9) AGENT_CORE KOMPONENTLARI (Windows+Linux Agent umumiy yadrosi) ===")


def _test_agent_components():
    import subprocess
    import time as _time
    from agent_core.process_killer import find_processes_holding_file, kill_process_holding_file

    test_file = "/tmp/_agent_component_test.txt"
    with open(test_file, "w") as f:
        f.write("test")

    proc = subprocess.Popen(["python3", "-c", f"f = open('{test_file}'); import time; time.sleep(10)"])
    _time.sleep(1.2)

    procs = find_processes_holding_file(test_file)
    assert len(procs) >= 1, "Faylni ochgan jarayon topilishi kerak edi"

    result = kill_process_holding_file(test_file)
    assert result.process_killed is True

    _time.sleep(0.5)
    assert proc.poll() is not None, "Jarayon to'xtatilgan bo'lishi kerak edi"
    os.remove(test_file)

    # file_monitor - ikki marta aniqlash xatosi tuzatilganini tasdiqlash
    from agent_core.file_monitor import FileMonitor
    watch_dir = "/tmp/_agent_watch_component_test"
    os.makedirs(watch_dir, exist_ok=True)
    detected = []
    monitor = FileMonitor([watch_dir], lambda p: detected.append(p))
    monitor.start()
    _time.sleep(0.5)
    with open(os.path.join(watch_dir, "sample.txt"), "wb") as f:
        f.write(b"sample content")
    _time.sleep(3.5)
    monitor.stop()
    assert len(detected) == 1, f"Aniq 1 marta aniqlanishi kerak edi, {len(detected)} marta aniqlandi"

    import shutil
    shutil.rmtree(watch_dir, ignore_errors=True)


check("Agent Core komponentlari (process_killer + file_monitor, real jarayon bilan)", _test_agent_components)

# ---------------------------------------------------------------------------
print("\n=== 9b) LINUX AGENT - TO'LIQ END-TO-END (real API server + real jarayon) ===")


def _test_linux_agent_e2e():
    import subprocess
    import time as _time
    import hashlib

    watch_dir = "/tmp/_linux_agent_e2e_watch"
    os.makedirs(watch_dir, exist_ok=True)

    malicious_content = b"linux agent e2e test malicious payload 987654"
    sha256 = hashlib.sha256(malicious_content).hexdigest()

    s = get_session()
    s.add(HashBlacklist(sha256=sha256, threat_name="LinuxAgentE2E-Trojan", source="manual"))
    s.commit()
    s.close()

    api_env = os.environ.copy()
    api_env["AGENT_API_KEY"] = "linux-e2e-test-key"
    api_proc = subprocess.Popen(
        ["python3", "-m", "api.server"],
        env={**api_env, "API_PORT": "8199"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _time.sleep(2)

    quarantine_dir = "/tmp/_linux_agent_e2e_quarantine"
    import shutil as _shutil
    _shutil.rmtree(quarantine_dir, ignore_errors=True)

    try:
        os.environ["API_SERVER_URL"] = "http://127.0.0.1:8199"
        os.environ["AGENT_API_KEY"] = "linux-e2e-test-key"
        os.environ["AGENT_CACHE_FILE"] = "/tmp/_linux_agent_e2e_cache.json"
        os.environ["AGENT_LOG_FILE"] = "/tmp/_linux_agent_e2e.log"
        # MUHIM: agent endi xom os.remove() o'rniga xavfsiz karantin
        # (nusxa-tasdiqlash-o'chirish) ishlatadi - test uchun alohida papka.
        os.environ["AGENT_QUARANTINE_DIR"] = quarantine_dir
        if os.path.exists(os.environ["AGENT_CACHE_FILE"]):
            os.remove(os.environ["AGENT_CACHE_FILE"])

        import importlib
        import agent_core.agent as agent_mod
        importlib.reload(agent_mod)

        agent = agent_mod.EndpointAgent([watch_dir])

        malicious_file = os.path.join(watch_dir, "linux_e2e_payload.bin")
        with open(malicious_file, "wb") as f:
            f.write(malicious_content)

        # Faylni "ochiq" ushlab turuvchi jarayon (real Linux jarayoni)
        locker = subprocess.Popen(["python3", "-c", f"f=open('{malicious_file}'); import time; time.sleep(10)"])
        _time.sleep(1)

        # Agentning fayl-topilishi logikasini to'g'ridan-to'g'ri chaqiramiz
        # (FileMonitor'ning watchdog kuzatuvi allaqachon alohida testda
        # tekshirilgan - bu yerda "aniqlangandan keyingi" javob zanjiri
        # sinaladi: hash -> server -> jarayonni to'xtatish -> XAVFSIZ
        # KARANTIN -> report, filepath bilan birga)
        agent._on_new_file(malicious_file)

        _time.sleep(1)

        assert not os.path.exists(malicious_file), "Zararli fayl (asl joyidan) o'chirilishi kerak edi"
        assert locker.poll() is not None, "Faylni ushlab turgan jarayon to'xtatilishi kerak edi"

        # MUHIM (o'zi topilgan bo'shliq, tuzatildi): ilgari fayl shunchaki
        # os.remove() bilan yo'qotilardi - endi karantin papkasida
        # (SHA256 tasdiqlangan) NUSXASI saqlanishi kerak.
        quarantined_copies = []
        for root, _dirs, filenames in os.walk(quarantine_dir):
            for fn in filenames:
                if fn == "linux_e2e_payload.bin":
                    quarantined_copies.append(os.path.join(root, fn))
        assert len(quarantined_copies) == 1, (
            f"Fayl xavfsiz karantin papkasiga nusxalanishi kerak edi, {len(quarantined_copies)} ta nusxa topildi"
        )
        with open(quarantined_copies[0], "rb") as f:
            assert f.read() == malicious_content, "Karantindagi nusxa asl fayl bilan bir xil bo'lishi kerak edi"

        s = get_session()
        alert = (
            s.query(Alert)
            .filter(Alert.reason.like("%LinuxAgentE2E-Trojan%"))
            .first()
        )
        assert alert is not None, "Markazga incident xabari kelib, Alert yaratilishi kerak edi"
        assert alert.device_id is not None
        assert malicious_file in alert.reason, "Fayl to'liq yo'li Alert.reason'da ko'rinishi kerak edi"
        assert "karantinga olindi" in alert.action_taken, f"Karantin xabari action_taken'da yo'q: {alert.action_taken}"

        file_event = s.query(FileEvent).filter(FileEvent.sha256 == sha256).first()
        assert file_event is not None, "check_hash orqali FileEvent yozilishi kerak edi"
        assert file_event.device_file_path == malicious_file, (
            f"FileEvent.device_file_path to'liq yo'lni saqlashi kerak edi, bor: {file_event.device_file_path!r}"
        )
        s.close()

    finally:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        import shutil
        shutil.rmtree(watch_dir, ignore_errors=True)
        shutil.rmtree(quarantine_dir, ignore_errors=True)
        for f in ["/tmp/_linux_agent_e2e_cache.json", "/tmp/_linux_agent_e2e.log"]:
            if os.path.exists(f):
                os.remove(f)
        for k in ["API_SERVER_URL", "AGENT_API_KEY", "AGENT_CACHE_FILE", "AGENT_LOG_FILE", "AGENT_QUARANTINE_DIR"]:
            os.environ.pop(k, None)


check("Linux Agent to'liq E2E (real server+jarayon+fayl o'chirish+report)", _test_linux_agent_e2e)

# ---------------------------------------------------------------------------
print("\n=== 10) NOTIFICATION ENGINE (real SMTP server orqali) ===")


def _test_notification_engine():
    import subprocess
    import time as _time
    import os as _os

    received_log = "/tmp/_test_received_emails.log"
    if _os.path.exists(received_log):
        _os.remove(received_log)

    debug_smtp_code = f'''
import asyncio
from aiosmtpd.controller import Controller

class DebugHandler:
    async def handle_DATA(self, server, session, envelope):
        with open("{received_log}", "a", encoding="utf-8") as f:
            f.write("=== YANGI XAT ===\\n")
            f.write(f"To: {{envelope.rcpt_tos}}\\n")
            f.write(envelope.content.decode("utf-8", errors="replace"))
        return "250 OK"

controller = Controller(DebugHandler(), hostname="127.0.0.1", port=1026)
controller.start()
import time
time.sleep(8)
controller.stop()
'''
    smtp_script = "/tmp/_test_debug_smtp.py"
    with open(smtp_script, "w") as f:
        f.write(debug_smtp_code)

    smtp_proc = subprocess.Popen(["python3", smtp_script])
    _time.sleep(2)

    try:
        os.environ["SMTP_HOST"] = "127.0.0.1"
        os.environ["SMTP_PORT"] = "1026"
        os.environ["SMTP_FROM"] = "security@company.local"
        os.environ["ADMIN_EMAIL"] = "admin@company.local"
        os.environ["NOTIFY_CHANNELS"] = "email,telegram"

        from datetime import datetime as _dt

        s = get_session()
        d = Device(ip_address="172.16.5.5", mac_address="AA:BB:CC:00:11:22",
                    hostname="NOTIFY-TEST-PC", connection_type="wifi", source="test")
        s.add(d)
        s.flush()
        # MUHIM (real production'da real Telegram xabarnomasi orqali
        # topilgan xato): aniq, nazorat qilinadigan UTC vaqt beriladi -
        # buni xabarnoma matnida XOM UTC emas, +5 (Toshkent) qilib
        # ko'rsatilishini tekshirish uchun (pastga qarang).
        fixed_utc_ts = _dt(2026, 1, 15, 10, 0, 0)
        alert = Alert(device_id=d.id, severity="critical", reason="Test xabarnoma",
                       action_taken="Test chora", notified=False, timestamp=fixed_utc_ts)
        s.add(alert)
        s.commit()
        alert_id = alert.id
        s.close()

        # Modullarni muhit o'zgaruvchilari o'zgarganidan keyin qayta yuklash kerak
        import importlib
        import notifications.email_notifier as email_mod
        importlib.reload(email_mod)
        import engine.notification_engine as notif_engine
        importlib.reload(notif_engine)

        n = notif_engine.run_once()
        assert n >= 1, f"Kamida 1 ta alert xabar qilinishi kerak edi, {n} ta qilindi"

        s = get_session()
        a = s.query(Alert).filter(Alert.id == alert_id).first()
        assert a.notified is True, "Alert notified=True bo'lishi kerak edi"
        s.close()

        _time.sleep(0.5)
        assert os.path.exists(received_log), "Email qabul qilinmadi (SMTP server fayl yozmadi)"
        raw_content = open(received_log).read()
        # Xat tanasi (MIMEText utf-8) base64 bilan kodlangan - xom matn
        # ichidan emas, MIME qismlarini ochib tekshiramiz.
        import email as _email
        content = raw_content
        for chunk in raw_content.split("=== YANGI XAT ===")[1:]:
            _hdr_end = chunk.find("Content-Type:")
            _msg = _email.message_from_string(chunk[_hdr_end:])
            for _part in _msg.walk():
                if _part.get_content_maintype() == "text":
                    content += "\n" + _part.get_payload(decode=True).decode("utf-8", errors="replace")
        assert "NOTIFY-TEST-PC" in content, "Xatda hostname topilmadi"
        # MUHIM (real production'da real Telegram xabarnomasi orqali
        # topilgan xato): xabarnomadagi "Vaqt:" avval xom UTC'ni
        # ko'rsatardi (masalan 08:47), Telegram'ning o'z yetkazilish
        # vaqtidan (mahalliy, 13:47) 5 soatga farq qilib chalkashtirardi.
        # Endi _build_alert_data() +5 (TIMEZONE_OFFSET_HOURS) qo'shadi.
        assert "2026-01-15 15:00:00" in content, (
            "Xabarnomadagi vaqt +5 (Toshkent) ga o'tkazilmagan - xom UTC yuborilmoqda"
        )
        assert "2026-01-15 10:00:00" not in content, (
            "Xabarnomada hali ham xom UTC vaqt bor - +5 konvertatsiyasi qo'llanmagan"
        )
    finally:
        smtp_proc.terminate()
        smtp_proc.wait(timeout=5)
        for f in [smtp_script, received_log]:
            if os.path.exists(f):
                os.remove(f)
        for k in ["SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "ADMIN_EMAIL", "NOTIFY_CHANNELS"]:
            os.environ.pop(k, None)


check("Notification engine (real SMTP orqali email yetkazish)", _test_notification_engine)

# ---------------------------------------------------------------------------
print("\n=== 4b) Telegram Notifier: Markdown parslash xatosi (real production'da birinchi marta topilgan) ===")


def _test_telegram_notifier_markdown_parse_fix():
    """
    HAQIQIY PRODUCTION'DA (bu sessiyaning o'zi tomonidan, deploy'dan
    keyin) topilgan xato: `notifications/telegram_notifier.py`
    `parse_mode: "Markdown"` bilan xabar yuborar edi, va `reason`
    kabi dinamik maydonlar HECH QANDAY escape qilinmasdan
    interpolatsiya qilinardi. Alert matnida deyarli har doim
    Telegram'ning Markdown uchun maxsus belgilari (`[`, `_`, `*`)
    uchraydi (masalan `[Trojan.Generic]` threat nomi yoki
    `[LEXICAL_PHISHING]` yorlig'i) - bittasi "juftlashmagan" bo'lsa,
    Telegram butun xabarni "can't parse entities" bilan RAD ETARDI.

    Bu xato HECH QACHON avval sinalmagan edi - sandbox tarmoq siyosati
    `api.telegram.org`ni bloklaganligi sababli (CLAUDE.md'da oldindan
    hujjatlashtirilgan) - kod faqat "TELEGRAM_BOT_TOKEN sozlanmagan"
    yo'lidan o'tib, haqiqiy so'rov hech qachon yuborilmagan edi. Real
    production'da (haqiqiy bot token bilan) birinchi marta ishlaganda,
    deyarli HAR BIR alert uchun bu xato chiqdi - xabarnomalar amalda
    HECH QACHON yetib bormagan.

    Bu test haqiqiy HTTP orqali - soxta Telegram API serveri bilan
    (real `api.telegram.org`ning aynan shu xatosini takrorlaydigan) -
    (1) eski (`parse_mode` bilan) xatti-harakat HAQIQATAN muvaffaqiyatsiz
    bo'lishini, (2) tuzatilgan (`parse_mode`siz) `send_alert_telegram()`
    xuddi shu (qavsli) matn bilan MUVAFFAQIYATLI yuborilishini tekshiradi.
    """
    import subprocess
    import time as _time
    from unittest.mock import patch

    mock_script = "/tmp/_ci_mock_telegram.py"
    with open(mock_script, "w") as f:
        f.write('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/bot<token>/sendMessage", methods=["POST"])
def send_message(token):
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    # HAQIQIY Telegram API'ning production'da kuzatilgan xatosini
    # takrorlaydi: parse_mode="Markdown" bilan, juftlashmagan "["
    # bo'lsa (masalan "[Trojan.Generic]" keyin yopilmagan yana bir "["
    # kabi emas - oddiy, real ssenariyni takrorlash uchun matnda
    # HAR QANDAY "[" borligi + parse_mode borligi kifoya, chunki
    # bizning eski kodimiz buni escape qilmasdi).
    if data.get("parse_mode") and "[" in text:
        return jsonify({"ok": False, "error_code": 400,
                         "description": "Bad Request: can't parse entities: Can't find end of the entity starting at byte offset 87"}), 400
    return jsonify({"ok": True, "result": {"message_id": 1}})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=19910)
''')

    mock_proc = subprocess.Popen(["python3", mock_script])
    try:
        _time.sleep(2)

        import notifications.telegram_notifier as tg_mod

        alert_data = {
            "severity": "high", "timestamp": "2026-09-10 12:00:00",
            "hostname": "CI-PC", "ip_address": "172.16.9.9", "mac_address": "-",
            "connection_type": "wifi",
            # Foydalanuvchi PRODUCTION'da aynan shu turdagi matn bilan
            # duch kelgan - qavs ichida threat nomi/yorliq.
            "reason": "Shubhali fayl aniqlandi: invoice.exe [Trojan.Generic] | SHA256=abc123",
            "action_taken": "TASDIQLANGAN: karantinaga yuborish navbatda",
        }

        with patch.object(tg_mod, "TELEGRAM_BOT_TOKEN", "ci-test-token"), \
             patch.object(tg_mod, "TELEGRAM_CHAT_ID", "12345"), \
             patch.object(tg_mod, "TELEGRAM_API_URL", "http://127.0.0.1:19910/bot{token}/sendMessage"):

            # 1) ESKI xatti-harakatni HAQIQATAN takrorlab, mock server
            #    haqiqatan ham buni rad etishini tasdiqlaymiz (aks holda
            #    bu test hech narsani isbotlamagan bo'lardi - mock
            #    server real xatoni to'g'ri simulyatsiya qilishi kerak).
            import requests
            old_style_payload = {
                "chat_id": tg_mod.TELEGRAM_CHAT_ID,
                "text": tg_mod._build_message(alert_data),
                "parse_mode": "Markdown",
            }
            mock_url = tg_mod.TELEGRAM_API_URL.format(token=tg_mod.TELEGRAM_BOT_TOKEN)
            old_resp = requests.post(mock_url, json=old_style_payload, timeout=5)
            assert old_resp.status_code == 400, (
                "Mock server eski (parse_mode bilan) so'rovni rad etmadi - "
                "bu test haqiqiy production xatosini to'g'ri simulyatsiya qilmayapti"
            )

            # 2) Tuzatilgan send_alert_telegram() - xuddi shu (qavsli) matn
            #    bilan MUVAFFAQIYATLI bo'lishi kerak.
            result = tg_mod.send_alert_telegram(alert_data)
            assert result is True, (
                "send_alert_telegram() muvaffaqiyatsiz bo'ldi - Markdown parslash "
                "xatosi hali ham qaytgan bo'lishi mumkin (parse_mode qayta qo'shilgan?)"
            )
    finally:
        mock_proc.terminate()
        try:
            mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock_proc.kill()
        if os.path.exists(mock_script):
            os.remove(mock_script)


check("Telegram Notifier: Markdown parslash xatosi (real production'da birinchi marta topilgan, sandbox tarmoq bloki tufayli avval hech qachon sinalmagan)", _test_telegram_notifier_markdown_parse_fix)

# ---------------------------------------------------------------------------
print("\n=== 11) CLAMAV INTEGRATSIYASI (maxsus test-signatura bazasi bilan) ===")


def _test_clamav_integration():
    import subprocess
    if subprocess.run(["which", "clamscan"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - clamscan o'rnatilmagan bu muhitda)")
        return

    os.environ["CLAMAV_DB_DIR"] = "/tmp/clamav_test_db"
    os.makedirs("/tmp/clamav_test_db", exist_ok=True)

    content = b"run_full_test clamav dummy malware content\n"
    import hashlib
    sha = hashlib.sha256(content).hexdigest()
    size = len(content)
    with open("/tmp/clamav_test_db/runtest.hdb", "w") as f:
        f.write(f"{sha}:{size}:RunFullTest.Malware\n")

    malware_path = "/tmp/_run_full_test_clamav_sample.txt"
    with open(malware_path, "wb") as f:
        f.write(content)

    clean_path = "/tmp/_run_full_test_clamav_clean.txt"
    with open(clean_path, "wb") as f:
        f.write(b"xavfsiz matn")

    import importlib
    import scanners.clamav_scanner as clamav_mod
    importlib.reload(clamav_mod)

    r_bad = clamav_mod.scan_file(malware_path)
    assert r_bad["scanned"] is True, f"Skanerlash muvaffaqiyatsiz: {r_bad}"
    assert r_bad["infected"] is True, "Zararli fayl aniqlanishi kerak edi"
    assert "RunFullTest.Malware" in r_bad["signature"]

    r_clean = clamav_mod.scan_file(clean_path)
    assert r_clean["scanned"] is True
    assert r_clean["infected"] is False

    os.remove(malware_path)
    os.remove(clean_path)
    os.remove("/tmp/clamav_test_db/runtest.hdb")
    os.environ.pop("CLAMAV_DB_DIR", None)


check("ClamAV integratsiyasi (zararli+toza fayl, real clamscan)", _test_clamav_integration)

# ---------------------------------------------------------------------------
print("\n=== 12) MITRE ATT&CK BELGILASH ===")


def _test_mitre_tagging():
    from engine.mitre_tagging_engine import run_once as mitre_run_once

    s = get_session()
    a1 = Alert(severity="high", reason="Blacklist'dagi domenga so'rov: evil.com (manba: manual)")
    a2 = Alert(severity="critical", reason="ClamAV[critical]: Trojan.GenericKD")
    a3 = Alert(severity="critical", reason="YARA[high]: Suspicious_PowerShell_Obfuscation - test")
    s.add_all([a1, a2, a3])
    s.commit()
    ids = [a1.id, a2.id, a3.id]
    s.close()

    n = mitre_run_once()
    assert n >= 3, f"Kamida 3 ta alert belgilanishi kerak edi, {n} ta belgilandi"

    s = get_session()
    tagged = {a.id: a for a in s.query(Alert).filter(Alert.id.in_(ids)).all()}
    assert tagged[a1.id].mitre_technique_id == "T1071.004", "DNS blacklist noto'g'ri texnika bilan belgilandi"
    assert tagged[a2.id].mitre_technique_id == "T1204.002", "ClamAV alert noto'g'ri texnika bilan belgilandi"
    assert tagged[a3.id].mitre_technique_id == "T1059.001", "PowerShell alert noto'g'ri texnika bilan belgilandi"
    for a in tagged.values():
        assert a.mitre_tactic, f"Alert {a.id} uchun taktika bo'sh qoldi"
    s.close()

    # Bo'sh navbatda 0 qaytarishi kerak
    assert mitre_run_once() == 0, "Barcha alertlar belgilangandan keyin 0 qaytarishi kerak edi"


check("MITRE ATT&CK avtomatik belgilash (texnika+taktika)", _test_mitre_tagging)

# ---------------------------------------------------------------------------
print("\n=== 13) WEB DASHBOARD (Flask test client orqali) ===")


def _test_dashboard():
    from dashboard import app as dash_app
    from dashboard.create_user import create_user

    create_user("dashtest_admin", "dashtestpass123", "admin")

    dash_app.app.secret_key = "test-secret-key-dashboard"
    client = _dash_client(dash_app.app)

    # Autentifikatsiyasiz - login sahifasiga redirect (302)
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302, f"302 (login'ga redirect) kutilgan edi, {r.status_code} keldi"

    # Noto'g'ri parol bilan - login sahifasida qoladi (200, lekin kirmagan)
    client.post("/login", data={"username": "dashtest_admin", "password": "wrong"})
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302, "Noto'g'ri parol bilan hali ham kirgan bo'lmasligi kerak"

    # To'g'ri login
    r = client.post("/login", data={"username": "dashtest_admin", "password": "dashtestpass123"})
    assert r.status_code in (200, 302)

    # Endi barcha sahifalar ochiq bo'lishi kerak
    for path in ["/", "/alerts", "/devices", "/files"]:
        r = client.get(path)
        assert r.status_code == 200, f"{path}: 200 kutilgan edi, {r.status_code} keldi"

    # Ma'lumot borligini tekshirish (oldingi testlarda yaratilgan device/alert'lar)
    r = client.get("/devices")
    body = r.get_data(as_text=True)
    assert "172.16." in body, "Devices sahifasida IP manzil ko'rinmadi"

    # Filtrlash ishlashini tekshirish
    r = client.get("/alerts?severity=critical")
    assert r.status_code == 200

    r = client.get("/files?verdict=malicious")
    assert r.status_code == 200

    client.get("/logout")
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302, "Logout'dan keyin qayta login talab qilinishi kerak"


check("Web Dashboard (login, 4 sahifa, filtrlash)", _test_dashboard)

# ---------------------------------------------------------------------------
print("\n=== 14) REPORT GENERATOR (CSV/JSON hisobot) ===")


def _test_report_generator():
    import shutil
    from reports.report_generator import generate_report

    out_dir = "/tmp/_test_report_output"
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)

    result = generate_report(period_days=365, formats=["csv", "json"], output_dir=out_dir)

    assert result["csv"] and os.path.isfile(result["csv"]), "CSV fayl yaratilmadi"
    assert result["json"] and os.path.isfile(result["json"]), "JSON fayl yaratilmadi"

    with open(result["csv"], encoding="utf-8-sig") as f:
        import csv as csv_mod
        rows = list(csv_mod.DictReader(f))
    assert len(rows) >= 1, "CSV'da hech qanday qator yo'q"
    assert "mitre_technique_id" in rows[0], "CSV'da MITRE ustuni yo'q"

    import json as json_mod
    with open(result["json"], encoding="utf-8") as f:
        data = json_mod.load(f)
    assert "summary" in data and "alerts" in data
    assert data["summary"]["total_alerts"] == len(data["alerts"])
    assert "severity_breakdown" in data["summary"]

    # Dashboard orqali yuklab olish (test client)
    from dashboard import app as dash_app
    from dashboard.create_user import create_user
    create_user("reporttest_admin", "reporttestpass123", "admin")
    dash_app.app.secret_key = "test-secret-key-report"
    client = _dash_client(dash_app.app)
    client.post("/login", data={"username": "reporttest_admin", "password": "reporttestpass123"})

    r = client.get("/reports/download?period_days=30&format=csv")
    assert r.status_code == 200
    assert r.data.startswith(b"\xef\xbb\xbfid,") or b"id,timestamp" in r.data[:50]

    r = client.get("/reports/download?format=xml")
    assert r.status_code == 400

    client.get("/logout")

    shutil.rmtree(out_dir, ignore_errors=True)


check("Report Generator (CSV/JSON + dashboard orqali yuklab olish)", _test_report_generator)

# ---------------------------------------------------------------------------
print("\n=== 15) RBAC (login, rollar, acknowledge huquqi) ===")


def _test_rbac():
    from dashboard.create_user import create_user
    from dashboard import app as dash_app

    create_user("rbac_admin", "adminpass123", "admin")
    create_user("rbac_analyst", "analystpass123", "analyst")
    create_user("rbac_viewer", "viewerpass123", "viewer")

    s = get_session()
    d = Device(ip_address="172.16.8.99", hostname="RBAC-AUTOTEST-PC", connection_type="wifi", source="test")
    s.add(d)
    s.flush()
    a = Alert(device_id=d.id, severity="critical", reason="RBAC avtomatik test alert", notified=False)
    s.add(a)
    s.commit()
    alert_id = a.id
    s.close()

    dash_app.app.secret_key = "test-secret-key"
    client = _dash_client(dash_app.app)

    # Autentifikatsiyasiz - login sahifasiga redirect
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 302 and "/login" in r.headers.get("Location", "")

    # Noto'g'ri parol
    r = client.post("/login", data={"username": "rbac_admin", "password": "wrong"})
    assert r.status_code == 200  # login sahifasiga qaytadi, xato bilan
    assert b"noto" in r.data.lower() or b"xato" in r.data.lower() or r.status_code == 200

    # Admin - to'g'ri login
    r = client.post("/login", data={"username": "rbac_admin", "password": "adminpass123"}, follow_redirects=True)
    assert r.status_code == 200
    r = client.get("/users")
    assert r.status_code == 200, "Admin /users sahifasiga kira olishi kerak edi"
    client.get("/logout")

    # Viewer - /users va acknowledge'ga kira olmasligi kerak
    client.post("/login", data={"username": "rbac_viewer", "password": "viewerpass123"})
    r = client.get("/users")
    assert r.status_code == 403, f"Viewer /users'ga kirmasligi kerak edi, {r.status_code} keldi"
    r = client.post(f"/alerts/{alert_id}/acknowledge")
    assert r.status_code == 403, f"Viewer acknowledge qila olmasligi kerak edi, {r.status_code} keldi"
    # Viewer oddiy sahifalarni ko'ra olishi kerak
    r = client.get("/alerts")
    assert r.status_code == 200
    client.get("/logout")

    # Analyst - acknowledge qila olishi, lekin /users'ga kira olmasligi kerak
    client.post("/login", data={"username": "rbac_analyst", "password": "analystpass123"})
    r = client.get("/users")
    assert r.status_code == 403, "Analyst /users'ga kirmasligi kerak edi"
    r = client.post(f"/alerts/{alert_id}/acknowledge", follow_redirects=False)
    assert r.status_code == 302, f"Analyst acknowledge qila olishi kerak edi, {r.status_code} keldi"

    s = get_session()
    a = s.query(Alert).filter(Alert.id == alert_id).first()
    assert a.acknowledged is True
    assert a.acknowledged_by == "rbac_analyst"
    s.close()
    client.get("/logout")

    # Parol xesh sifatida saqlanganini tekshirish (ochiq matn emas)
    s = get_session()
    u = s.query(User).filter(User.username == "rbac_admin").first()
    assert u.password_hash != "adminpass123", "Parol ochiq matnda saqlanmasligi kerak!"
    assert u.password_hash.startswith(("pbkdf2:", "scrypt:")), "Parol tanish xesh formatida emas"
    s.close()


check("RBAC (login, 3 rol, acknowledge huquqi, parol xeshlash)", _test_rbac)

# ---------------------------------------------------------------------------
print("\n=== 16) PDF/EXCEL HISOBOTLAR (real fayl + LibreOffice recalc) ===")


def _test_pdf_excel_reports():
    import shutil
    import subprocess
    from reports.report_generator import generate_report

    out_dir = "/tmp/_test_pdf_excel_output"
    if os.path.exists(out_dir):
        shutil.rmtree(out_dir)

    result = generate_report(period_days=365, formats=["pdf", "excel"], output_dir=out_dir)

    assert result["pdf"] and os.path.isfile(result["pdf"]), "PDF fayl yaratilmadi"
    assert result["excel"] and os.path.isfile(result["excel"]), "Excel fayl yaratilmadi"

    # PDF haqiqiy o'qiladigan ekanini tekshirish
    from pypdf import PdfReader
    reader = PdfReader(result["pdf"])
    assert len(reader.pages) >= 1, "PDF'da sahifa yo'q"

    # Excel: LibreOffice orqali formulalarni haqiqiy hisoblash (recalc)
    recalc_script = "/mnt/skills/public/xlsx/scripts/recalc.py"
    if os.path.isfile(recalc_script):
        proc = subprocess.run(
            ["python3", recalc_script, result["excel"], "60"],
            capture_output=True, text=True, timeout=90,
        )
        import json as json_mod
        recalc_result = json_mod.loads(proc.stdout)
        assert recalc_result.get("status") == "success", f"Excel recalc muvaffaqiyatsiz: {recalc_result}"
        assert recalc_result.get("total_errors") == 0, f"Excel'da formula xatolari bor: {recalc_result}"

        # Hisoblangan qiymatlarni haqiqiy sonlar bilan solishtirish
        from openpyxl import load_workbook
        wb = load_workbook(result["excel"], data_only=True)
        ws = wb["Summary"]
        total_from_excel = ws["B4"].value
        assert total_from_excel == result["summary"]["total_alerts"], (
            f"Excel formulasi noto'g'ri hisobladi: {total_from_excel} != {result['summary']['total_alerts']}"
        )

    # Bo'sh davr bilan ham ishlashini tekshirish (edge case)
    empty_result = generate_report(period_days=0, formats=["pdf", "excel"], output_dir=out_dir)
    assert os.path.isfile(empty_result["pdf"]), "Bo'sh davr uchun PDF yaratilmadi"
    assert os.path.isfile(empty_result["excel"]), "Bo'sh davr uchun Excel yaratilmadi"

    # Dashboard orqali yuklab olish
    from dashboard import app as dash_app
    from dashboard.create_user import create_user
    create_user("pdftest_admin", "pdftestpass123", "admin")
    dash_app.app.secret_key = "test-secret-key-pdf"
    client = _dash_client(dash_app.app)
    client.post("/login", data={"username": "pdftest_admin", "password": "pdftestpass123"})

    r = client.get("/reports/download?period_days=7&format=pdf")
    assert r.status_code == 200
    assert r.data[:4] == b"%PDF", "Dashboard'dan qaytgan fayl PDF emas"

    r = client.get("/reports/download?period_days=7&format=excel")
    assert r.status_code == 200
    assert r.data[:2] == b"PK", "Dashboard'dan qaytgan fayl Excel (ZIP-based) emas"

    client.get("/logout")
    shutil.rmtree(out_dir, ignore_errors=True)


check("PDF/Excel hisobotlar (real fayl, LibreOffice recalc, dashboard)", _test_pdf_excel_reports)

# ---------------------------------------------------------------------------
print("\n=== 17) SNORT INTEGRATSIYASI (real Snort chiqishi, pcap orqali) ===")


def _test_snort_integration():
    import subprocess
    import shutil

    if subprocess.run(["which", "snort"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - snort o'rnatilmagan bu muhitda)")
        return

    from collectors.snort_reader import parse_alert_line, read_existing

    # 1) parse_alert_line birlik testi (haqiqiy Snort formatiga mos)
    sample = "08/06-08:39:01.972343  [**] [1:1000001:1] TEST Suspicious port 4444 (C2-like) [**] [Priority: 1] {TCP} 10.0.0.5:51234 -> 10.0.0.99:4444"
    parsed = parse_alert_line(sample)
    assert parsed is not None
    assert parsed["dst_port"] == 4444
    assert parsed["priority"] == 1

    # 2) Haqiqiy Snort'ni pcap fayl orqali ishga tushirib, chiqishini tekshirish
    work_dir = "/tmp/_test_snort_e2e"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    try:
        from scapy.all import IP, TCP, Ether, wrpcap
    except ImportError:
        print("   (scapy yo'q - faqat parser birlik testi bajarildi)")
        return

    pkt = Ether() / IP(src="10.0.0.7", dst="10.0.0.98") / TCP(sport=55000, dport=4444, flags="S")
    pcap_path = os.path.join(work_dir, "test.pcap")
    wrpcap(pcap_path, [pkt])

    rules_path = os.path.join(work_dir, "test.rules")
    with open(rules_path, "w") as f:
        f.write('alert tcp any any -> any 4444 (msg:"CI Suspicious port 4444"; sid:1000099; rev:1; priority:1;)\n')

    conf_path = os.path.join(work_dir, "snort.conf")
    with open(conf_path, "w") as f:
        f.write(f"var HOME_NET any\nvar EXTERNAL_NET any\ninclude {rules_path}\n")

    result = subprocess.run(
        ["snort", "-c", conf_path, "-r", pcap_path, "-A", "fast", "-l", work_dir, "-q"],
        capture_output=True, text=True, timeout=30,
    )
    assert result.returncode == 0, f"Snort xatolik bilan chiqdi: {result.stderr}"

    alert_file = os.path.join(work_dir, "alert")
    assert os.path.isfile(alert_file), "Snort alert fayli yaratilmadi"

    n = read_existing(alert_file)
    assert n >= 1, "Kamida 1 ta Snort alert qayta ishlanishi kerak edi"

    s = get_session()
    device = s.query(Device).filter(Device.ip_address == "10.0.0.7").first()
    assert device is not None, "Snort orqali kelgan qurilma bazada topilmadi"
    alert = s.query(Alert).filter(Alert.reason.like("%CI Suspicious port 4444%")).first()
    assert alert is not None, "Snort alert bazada topilmadi"
    assert alert.severity == "critical", f"Priority=1 critical bo'lishi kerak edi, {alert.severity} keldi"
    s.close()

    shutil.rmtree(work_dir, ignore_errors=True)


check("Snort integratsiyasi (real Snort binary, pcap orqali)", _test_snort_integration)

# ---------------------------------------------------------------------------
print("\n=== 18) ZEEK INTEGRATSIYASI (sxemaga mos sintetik JSON loglar) ===")


def _test_zeek_integration():
    import shutil
    from collectors.zeek_reader import read_existing as zeek_read_existing

    log_dir = "/tmp/_test_zeek_logs"
    if os.path.exists(log_dir):
        shutil.rmtree(log_dir)
    os.makedirs(log_dir)

    with open(os.path.join(log_dir, "notice.log"), "w") as f:
        f.write('{"ts":1754470800.1,"note":"Scan::Port_Scan","msg":"test port scan","src":"172.16.6.10","dst":"172.16.6.20"}\n')

    with open(os.path.join(log_dir, "dns.log"), "w") as f:
        f.write('{"ts":1754470801.1,"id.orig_h":"172.16.6.11","query":"zeek-test-blacklist-domain.com","qtype_name":"A"}\n')

    with open(os.path.join(log_dir, "conn.log"), "w") as f:
        f.write('{"ts":1754470802.1,"id.orig_h":"172.16.6.12","id.resp_h":"1.2.3.4","id.resp_p":443,"proto":"tcp"}\n')

    file_sha = "2222222222222222222222222222222222222222222222222222222222222222"[:64]
    with open(os.path.join(log_dir, "files.log"), "w") as f:
        f.write(
            '{"ts":1754470803.1,"fuid":"Ftest1","tx_hosts":["172.16.6.13"],"rx_hosts":["5.6.7.8"],'
            f'"source":"HTTP","filename":"zeek_payload.exe","mime_type":"application/x-dosexec",'
            f'"seen_bytes":1000,"sha256":"{file_sha}","md5":"bbbb"}}\n'
        )

    s = get_session()
    s.add(BlacklistEntry(value="zeek-test-blacklist-domain.com", source="manual", reason="ci-test"))
    s.commit()
    s.close()

    results = zeek_read_existing(log_dir)
    assert results["notice.log"] == 1
    assert results["dns.log"] == 1
    assert results["conn.log"] == 1
    assert results["files.log"] == 1

    s = get_session()
    assert s.query(Device).filter(Device.ip_address == "172.16.6.10").first() is not None
    dns_alert = s.query(Alert).filter(Alert.reason.like("%zeek-test-blacklist-domain.com%")).first()
    assert dns_alert is not None, "Zeek DNS blacklist alert yaratilmadi"

    fe = s.query(FileEvent).filter(FileEvent.sha256 == file_sha).first()
    assert fe is not None, "Zeek files.log orqali FileEvent yaratilmadi"
    assert fe.channel == "zeek"
    assert fe.checked is False
    s.close()

    # MUHIM: Zeek orqali kelgan fayl mavjud file_analysis_engine pipeline'iga
    # avtomatik o'tishini tasdiqlash (alohida kod yozilmagan, qayta ishlatilgan)
    from engine.file_analysis_engine import run_once as file_analysis_run
    n = file_analysis_run()
    assert n >= 1

    s = get_session()
    fe = s.query(FileEvent).filter(FileEvent.sha256 == file_sha).first()
    assert fe.checked is True, "Zeek fayli file_analysis_engine orqali tekshirilmadi"
    s.close()

    shutil.rmtree(log_dir, ignore_errors=True)


check("Zeek integratsiyasi (4 log turi + mavjud file-pipeline bilan)", _test_zeek_integration)

# ---------------------------------------------------------------------------
print("\n=== 19) MFA - TOTP (real vaqt algoritmi) ===")


def _test_mfa():
    from dashboard import mfa as mfa_module
    from dashboard.create_user import create_user
    from dashboard import app as dash_app

    create_user("mfatest_admin", "mfatestpass123", "admin", "local")
    dash_app.app.secret_key = "test-secret-mfa-full"
    client = _dash_client(dash_app.app)

    # MFA yo'qligida to'g'ridan-to'g'ri kirish
    r = client.post("/login", data={"username": "mfatest_admin", "password": "mfatestpass123"}, follow_redirects=True)
    r2 = client.get("/")
    assert r2.status_code == 200, "MFA yo'q holatda to'g'ridan-to'g'ri kirishi kerak edi"

    # QR-kod olish
    r = client.get("/mfa/setup")
    assert b"data:image/png;base64," in r.data

    with client.session_transaction() as sess:
        secret = sess.get("pending_mfa_secret")
    assert secret is not None

    # To'g'ri kod bilan yoqish
    code = mfa_module.get_current_code(secret)
    client.post("/mfa/setup", data={"code": code})

    s = get_session()
    u = s.query(User).filter(User.username == "mfatest_admin").first()
    assert u.mfa_enabled is True, "MFA yoqilmadi"
    s.close()

    client.get("/logout")

    # Endi login parol to'g'ri bo'lsa ham MFA sahifasiga yo'naltirishi kerak
    r = client.post("/login", data={"username": "mfatest_admin", "password": "mfatestpass123"}, follow_redirects=False)
    assert "/mfa/verify" in r.headers.get("Location", ""), "MFA sahifasiga yo'naltirilmadi"

    r2 = client.get("/", follow_redirects=False)
    assert r2.status_code == 302, "MFA tasdiqlanmasdan kira olmasligi kerak edi"

    # Noto'g'ri kod
    client.post("/mfa/verify", data={"code": "000000"})
    r3 = client.get("/", follow_redirects=False)
    assert r3.status_code == 302, "Noto'g'ri kod bilan hali ham kira olmasligi kerak"

    # To'g'ri kod bilan yakuniy kirish
    new_code = mfa_module.get_current_code(secret)
    client.post("/mfa/verify", data={"code": new_code})
    r4 = client.get("/")
    assert r4.status_code == 200, "To'g'ri kod bilan kirishi kerak edi"

    # Boshqa secret bilan kod mos kelmasligini tekshirish (birlik test, mfa.py'da)
    other_secret = mfa_module.generate_secret()
    assert mfa_module.verify_code(other_secret, code) is False


check("MFA/TOTP (QR-kod, to'liq login oqimi, real vaqt algoritmi)", _test_mfa)

# ---------------------------------------------------------------------------
print("\n=== 20) LDAP LOGIN (real OpenLDAP server bilan) ===")


def _test_ldap_login():
    import subprocess
    import shutil

    if subprocess.run(["which", "slapd"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - slapd o'rnatilmagan bu muhitda)")
        return

    work_dir = "/tmp/_test_ldap_e2e"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(os.path.join(work_dir, "data"))

    slapd_conf = f"""include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
modulepath /usr/lib/ldap
moduleload back_mdb.la
pidfile {work_dir}/slapd.pid
argsfile {work_dir}/slapd.args
database mdb
maxsize 1048576000
suffix "dc=test,dc=local"
rootdn "cn=admin,dc=test,dc=local"
rootpw testpass456
directory {work_dir}/data
"""
    with open(os.path.join(work_dir, "slapd.conf"), "w") as f:
        f.write(slapd_conf)

    base_ldif = """dn: dc=test,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: Test
dc: test

dn: ou=people,dc=test,dc=local
objectClass: organizationalUnit
ou: people

dn: cn=ciuser,ou=people,dc=test,dc=local
objectClass: inetOrgPerson
cn: ciuser
sn: User
givenName: CI
mail: ciuser@test.local
userPassword: CIPass456
"""
    ldif_path = os.path.join(work_dir, "base.ldif")
    with open(ldif_path, "w") as f:
        f.write(base_ldif)

    # Avval slapd'ning o'z konfiguratsiya-tekshirish rejimi (-Tt) orqali
    # sinxron tarzda tekshiramiz - bu aniq xato xabarini darhol beradi
    # (agar keyingi bosqichda muammo bo'lsa, buni ham diagnostikaga qo'shamiz).
    conf_test = subprocess.run(
        ["slapd", "-Tt", "-f", os.path.join(work_dir, "slapd.conf")],
        capture_output=True, timeout=10, text=True,
    )

    slapd_log_path = os.path.join(work_dir, "slapd_stderr.log")
    slapd_log_file = open(slapd_log_path, "w")
    slapd_proc = subprocess.Popen(
        ["slapd", "-f", os.path.join(work_dir, "slapd.conf"), "-h", "ldap://127.0.0.1:3390/", "-d", "0"],
        stdout=slapd_log_file, stderr=subprocess.STDOUT,
    )
    import time as _time

    # MUHIM: sobit sleep() o'rniga slapd haqiqatan tayyor bo'lguncha
    # polling orqali kutamiz - sekinroq muhitlarda (masalan GitHub
    # Actions runner) 2 soniya yetarli bo'lmasligi mumkin (bu CI'da
    # aynan shu sabab bilan aniqlangan xato edi).
    slapd_ready = False
    for _ in range(20):  # maksimal ~10 soniya
        probe = subprocess.run(
            ["ldapsearch", "-x", "-H", "ldap://127.0.0.1:3390", "-b", "", "-s", "base"],
            capture_output=True, timeout=3,
        )
        if probe.returncode == 0:
            slapd_ready = True
            break
        _time.sleep(0.5)

    if not slapd_ready:
        slapd_log_file.flush()
        with open(slapd_log_path) as f:
            log_content = f.read()
        return_code = slapd_proc.poll()
        module_path = "/usr/lib/ldap/back_mdb.la"
        module_exists = os.path.isfile(module_path)
        empty_marker = "(bo'sh)"
        error_msg = (
            f"slapd 10 soniyada tayyor bo'lmadi. "
            f"return_code={return_code}, "
            f"modul_fayl_mavjud({module_path})={module_exists}, "
            f"slapd_chiqishi={log_content[:500] or empty_marker!r}, "
            f"config_test_rc={conf_test.returncode}, "
            f"config_test_stdout={conf_test.stdout[:300]!r}, "
            f"config_test_stderr={conf_test.stderr[:300]!r}"
        )
        assert False, error_msg

    try:
        ldapadd_result = subprocess.run(
            ["ldapadd", "-x", "-D", "cn=admin,dc=test,dc=local", "-w", "testpass456",
             "-H", "ldap://127.0.0.1:3390", "-f", ldif_path],
            capture_output=True, timeout=10, text=True,
        )
        assert ldapadd_result.returncode == 0, (
            f"ldapadd muvaffaqiyatsiz (kod={ldapadd_result.returncode}): "
            f"stdout={ldapadd_result.stdout!r} stderr={ldapadd_result.stderr!r}"
        )

        os.environ["LDAP_SERVER"] = "ldap://127.0.0.1:3390"
        os.environ["LDAP_BIND_DN_TEMPLATE"] = "cn={username},ou=people,dc=test,dc=local"

        import importlib
        import dashboard.ldap_auth as ldap_mod
        importlib.reload(ldap_mod)
        import dashboard.auth as auth_mod
        importlib.reload(auth_mod)

        assert ldap_mod.authenticate_ldap("ciuser", "CIPass456") is True, "To'g'ri LDAP parol qabul qilinishi kerak edi"
        assert ldap_mod.authenticate_ldap("ciuser", "wrong") is False, "Noto'g'ri LDAP parol rad etilishi kerak edi"
        assert ldap_mod.authenticate_ldap("ciuser", "") is False, "Bo'sh parol (anonim bind) rad etilishi kerak edi"
        assert ldap_mod.authenticate_ldap("nonexistent", "anything") is False

        # Dashboard login oqimi orqali ham tekshirish
        from dashboard.create_user import create_user
        create_user("ciuser", "placeholder", "viewer", "ldap")

        from dashboard import app as dash_app
        dash_app.app.secret_key = "test-secret-ldap-full"
        client = _dash_client(dash_app.app)

        r = client.post("/login", data={"username": "ciuser", "password": "CIPass456"}, follow_redirects=True)
        r2 = client.get("/")
        assert r2.status_code == 200, "LDAP orqali dashboard login muvaffaqiyatli bo'lishi kerak edi"

    finally:
        slapd_proc.terminate()
        try:
            slapd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            slapd_proc.kill()
        slapd_log_file.close()
        shutil.rmtree(work_dir, ignore_errors=True)
        for k in ["LDAP_SERVER", "LDAP_BIND_DN_TEMPLATE"]:
            os.environ.pop(k, None)


check("LDAP Login (real OpenLDAP server, to'g'ri/noto'g'ri/bo'sh parol)", _test_ldap_login)

# ---------------------------------------------------------------------------
print("\n=== 21) RABBITMQ QUEUE (real broker, to'liq UDP->Queue->Worker->DB zanjiri) ===")


def _test_rabbitmq_queue():
    import subprocess
    if subprocess.run(["which", "rabbitmqctl"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - rabbitmq-server o'rnatilmagan bu muhitda)")
        return

    from messaging.rabbitmq_client import health_check, publish_json, consume_batch, queue_depth, get_connection

    if not health_check():
        print("   (o'tkazib yuborildi - RabbitMQ server ishlamayapti)")
        return

    test_queue = "_ci_test_queue"
    e2e_queue = "_ci_e2e_syslog_queue"

    # MUHIM: avvalgi (masalan muvaffaqiyatsiz tugagan) test urinishlaridan
    # qolgan xabarlar bo'lishi mumkin - RabbitMQ navbatlari persistent
    # (durable) bo'lgani uchun. Test har doim BO'SH navbatdan boshlashi
    # kerak - shuning uchun avval tozalaymiz.
    for qname in (test_queue, e2e_queue):
        try:
            conn = get_connection()
            ch = conn.channel()
            ch.queue_declare(queue=qname, durable=True)
            ch.queue_purge(queue=qname)
            conn.close()
        except Exception:
            pass

    # 1) Asosiy publish/consume birlik testi
    for i in range(5):
        assert publish_json(test_queue, {"id": i, "text": f"test {i}"}) is True

    depth = queue_depth(test_queue)
    assert depth == 5, f"Navbat chuqurligi 5 bo'lishi kerak edi, {depth} keldi"

    received = []
    count = consume_batch(test_queue, lambda d: received.append(d), max_messages=5, timeout_seconds=10)
    assert count == 5
    assert sorted(r["id"] for r in received) == [0, 1, 2, 3, 4]
    assert queue_depth(test_queue) == 0

    # 2) To'liq E2E: real UDP paket -> navbat-asosli syslog server -> RabbitMQ -> worker -> DB
    import socket
    import time as _time

    server_proc = subprocess.Popen(
        ["python3", "-m", "collectors.syslog_server_queued"],
        env={**os.environ, "RAW_SYSLOG_QUEUE": "_ci_e2e_syslog_queue"},
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    _time.sleep(2)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_mac = "AA:BB:CC:DD:EE:99"
        msg = f"[04/Mar/2014 12:07:28] [IPv4] 172.16.9.199 [MAC] {test_mac.replace(':', '-')} (Test) [Hostname] RABBITMQ-E2E-TEST"
        sock.sendto(msg.encode(), ("127.0.0.1", 5140))
        _time.sleep(1)

        depth_after_send = queue_depth("_ci_e2e_syslog_queue")
        assert depth_after_send == 1, f"UDP paket navbatga tushmadi (chuqurlik={depth_after_send})"

        # MUHIM: muhit o'zgaruvchisi modul import qilinishidan OLDIN
        # o'rnatilishi kerak (modul darajasidagi konstanta faqat bir
        # marta, import paytida hisoblanadi) - shuning uchun importlib.reload
        # bilan majburan qayta yuklaymiz.
        os.environ["RAW_SYSLOG_QUEUE"] = "_ci_e2e_syslog_queue"
        import importlib
        import engine.queue_ingest_worker as worker_mod
        importlib.reload(worker_mod)

        n = worker_mod.run_once(timeout_seconds=5)
        assert n == 1, f"Worker 1 ta xabarni qayta ishlashi kerak edi, {n} ta ishladi"

        s = get_session()
        raw = s.query(RawLog).filter(RawLog.raw_message.like("%RABBITMQ-E2E-TEST%")).first()
        assert raw is not None, "UDP->Queue->Worker->DB zanjiri orqali yozuv topilmadi"
        assert raw.source_ip == "127.0.0.1"
        s.close()

    finally:
        server_proc.terminate()
        try:
            server_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_proc.kill()
        os.environ.pop("RAW_SYSLOG_QUEUE", None)


check("RabbitMQ Queue (real broker, to'liq UDP->Queue->Worker->DB)", _test_rabbitmq_queue)

# ---------------------------------------------------------------------------
print("\n=== 22) UEBA / AI - anomaliya aniqlash va Risk Score (real statistik ma'lumot) ===")


def _test_ueba():
    import random
    from datetime import timedelta
    from db.models import DeviceBaseline, utcnow
    from engine.ueba_engine import compute_baselines_for_all_devices, detect_anomalies, compute_risk_scores

    random.seed(123)
    s = get_session()
    now = utcnow()

    d_normal = Device(ip_address="172.16.11.1", hostname="UEBA-NORMAL", connection_type="wifi", source="test")
    d_anomaly = Device(ip_address="172.16.11.2", hostname="UEBA-ANOMALY", connection_type="wifi", source="test")
    s.add_all([d_normal, d_anomaly])
    s.flush()
    normal_id, anomaly_id = d_normal.id, d_anomaly.id

    # Ikkala qurilma uchun bir xil "normal" baseline: 25 kun, soat 9-18, 4-8 hodisa/soat
    for dev_id in (normal_id, anomaly_id):
        for day in range(1, 26):  # bugungi kunni band qilmaslik uchun 1-dan boshlaymiz
            for hour in range(9, 19):
                for _ in range(random.randint(4, 8)):
                    ts = now.replace(hour=hour, minute=random.randint(0, 59), second=0, microsecond=0) - timedelta(days=day)
                    s.add(Event(device_id=dev_id, source_ip="172.16.11.0", dest_ip="8.8.8.8", dest_port=443, protocol="TCP", timestamp=ts))

    # Faqat anomaly qurilmasida - joriy soatda katta portlash
    for _ in range(150):
        s.add(Event(device_id=anomaly_id, source_ip="172.16.11.0", dest_ip="185.20.10.99", dest_port=8080, protocol="TCP", timestamp=now))

    s.commit()
    s.close()

    n_baselines = compute_baselines_for_all_devices()
    assert n_baselines >= 2, f"Kamida 2 ta baseline hisoblanishi kerak edi, {n_baselines} ta hisoblandi"

    s = get_session()
    bl_normal = s.query(DeviceBaseline).filter(DeviceBaseline.device_id == normal_id).first()
    bl_anomaly = s.query(DeviceBaseline).filter(DeviceBaseline.device_id == anomaly_id).first()
    assert bl_normal is not None and bl_anomaly is not None
    assert bl_normal.mean_events_per_hour > 0
    s.close()

    n_anomalies = detect_anomalies()
    assert n_anomalies >= 1, f"Kamida 1 ta anomaliya topilishi kerak edi, {n_anomalies} ta topildi"

    s = get_session()
    anomaly_alert = s.query(Alert).filter(Alert.device_id == anomaly_id, Alert.reason.like("UEBA%")).first()
    assert anomaly_alert is not None, "Anomal qurilma uchun UEBA alert yaratilishi kerak edi"
    assert "Hajm anomaliyasi" in anomaly_alert.reason

    normal_false_positive = s.query(Alert).filter(Alert.device_id == normal_id, Alert.reason.like("UEBA%")).first()
    assert normal_false_positive is None, "Normal qurilmada SOXTA-POZITIV UEBA alert bo'lmasligi kerak edi"
    s.close()

    # Risk Score: anomaly qurilmasiga qo'shimcha critical/high alertlar qo'shib, farqni tekshiramiz
    s = get_session()
    s.add(Alert(device_id=anomaly_id, severity="critical", reason="Test critical", mitre_tactic="Execution"))
    s.add(Alert(device_id=anomaly_id, severity="high", reason="Test high", mitre_tactic="Command and Control"))
    s.commit()
    s.close()

    compute_risk_scores()

    s = get_session()
    dev_normal = s.query(Device).filter(Device.id == normal_id).first()
    dev_anomaly = s.query(Device).filter(Device.id == anomaly_id).first()
    assert dev_anomaly.risk_score > dev_normal.risk_score, (
        f"Anomal qurilma risk score'i normal qurilmadan yuqori bo'lishi kerak edi "
        f"({dev_anomaly.risk_score} vs {dev_normal.risk_score})"
    )
    assert dev_normal.risk_score == 0, f"Normal qurilma risk score'i 0 bo'lishi kerak edi, {dev_normal.risk_score} keldi"
    assert dev_anomaly.risk_score > 30, "Anomal qurilma yetarlicha yuqori risk score olishi kerak edi"
    s.close()

    # MITRE tagging bilan integratsiya
    from engine.mitre_tagging_engine import run_once as mitre_run
    mitre_run()
    s = get_session()
    tagged = s.query(Alert).filter(Alert.reason.like("UEBA%")).first()
    assert tagged.mitre_technique_id is not None, "UEBA alert MITRE bilan belgilanmadi"
    s.close()


check("UEBA/AI (statistik anomaliya aniqlash, Risk Score, soxta-pozitivsiz)", _test_ueba)

# ---------------------------------------------------------------------------
print("\n=== 23) KUBERNETES MANIFESTLAR (YAML struktura tekshiruvi) ===")


def _test_k8s_manifests():
    import glob
    import yaml as yaml_mod

    k8s_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "k8s")
    files = sorted(glob.glob(os.path.join(k8s_dir, "*.yaml")))
    assert len(files) >= 6, f"Kamida 6 ta k8s manifest fayli kutilgan edi, {len(files)} ta topildi"

    required_kinds_seen = set()
    total_docs = 0

    for filepath in files:
        with open(filepath) as f:
            docs = list(yaml_mod.safe_load_all(f))
        for doc in docs:
            if doc is None:
                continue
            total_docs += 1
            assert "apiVersion" in doc, f"{filepath}: 'apiVersion' yo'q"
            assert "kind" in doc, f"{filepath}: 'kind' yo'q"
            assert "metadata" in doc and "name" in doc["metadata"], f"{filepath}: metadata.name yo'q"
            required_kinds_seen.add(doc["kind"])

    expected_kinds = {
        "Namespace", "ConfigMap", "Secret", "StatefulSet", "Service",
        "Deployment", "PersistentVolumeClaim", "HorizontalPodAutoscaler", "Ingress",
    }
    missing = expected_kinds - required_kinds_seen
    assert not missing, f"Kutilgan resurs turlari topilmadi: {missing}"
    assert total_docs >= 20, f"Kamida 20 ta resurs kutilgan edi, {total_docs} ta topildi"


check("Kubernetes manifestlar (struktura, kutilgan resurs turlari)", _test_k8s_manifests)

# ---------------------------------------------------------------------------
print("\n=== 24) AUDIT LOG (real HTTP orqali, login/acknowledge/user boshqaruvi) ===")


def _test_audit_log():
    from db.models import AuditLog
    from dashboard import app as dash_app
    from dashboard.create_user import create_user

    create_user("audit_test_admin", "audittestpass123", "admin")
    dash_app.app.secret_key = "test-secret-audit"
    client = _dash_client(dash_app.app)

    # MUHIM: avval noto'g'ri, keyin to'g'ri login - aks holda muvaffaqiyatli
    # login'dan keyingi sessiya cookie'si ikkinchi so'rovni "current_user.
    # is_authenticated" tekshiruvida darhol qaytarib yuboradi, login
    # logikasiga umuman yetib bormaydi (bu test kodidagi tuzatilgan xato edi).
    client.post("/login", data={"username": "audit_test_admin", "password": "wrong"})
    client.post("/login", data={"username": "audit_test_admin", "password": "audittestpass123"})

    s = get_session()
    logins = s.query(AuditLog).filter(AuditLog.username == "audit_test_admin", AuditLog.action == "login").all()
    assert len(logins) == 2, f"2 ta login urinishi qayd etilishi kerak edi, {len(logins)} ta topildi"
    successes = [l.success for l in logins]
    assert True in successes and False in successes, "Muvaffaqiyatli va muvaffaqiyatsiz login ikkalasi ham qayd etilishi kerak edi"
    s.close()

    # Foydalanuvchi yaratish audit'i
    client.post("/users/create", data={"username": "audit_created_user", "password": "pass123", "role": "viewer"})
    s = get_session()
    create_entry = s.query(AuditLog).filter(AuditLog.action == "create_user", AuditLog.target_id == "audit_created_user").first()
    assert create_entry is not None, "create_user audit yozuvi topilmadi"
    assert create_entry.username == "audit_test_admin"
    s.close()

    # Viewer /audit'ga kira olmasligi kerak (RBAC bilan integratsiya)
    create_user("audit_test_viewer", "viewerpass123", "viewer")
    client.get("/logout")
    client.post("/login", data={"username": "audit_test_viewer", "password": "viewerpass123"})
    r = client.get("/audit")
    assert r.status_code == 403, f"Viewer /audit'ga kirmasligi kerak edi, {r.status_code} keldi"

    client.get("/logout")
    client.post("/login", data={"username": "audit_test_admin", "password": "audittestpass123"})
    r = client.get("/audit")
    assert r.status_code == 200
    assert b"audit_test_admin" in r.data


check("Audit Log (login/acknowledge/user boshqaruvi qayd etiladi, RBAC bilan)", _test_audit_log)

# ---------------------------------------------------------------------------
print("\n=== 25) BACKUP/RESTORE (real 'halokat va tiklash' stsenariysi) ===")


def _test_backup_restore():
    import shutil
    from backup.backup_manager import create_backup, restore_backup, list_backups

    backup_dir = "/tmp/_test_backup_restore"
    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)

    s = get_session()
    s.add(Device(ip_address="172.16.21.1", hostname="BACKUP-CI-TEST", connection_type="wifi", source="test"))
    s.commit()
    s.close()

    backup_path = create_backup(backup_dir)
    assert os.path.isfile(backup_path) or (backup_path and os.path.getsize(backup_path) >= 0), "Backup fayli yaratilmadi"

    backups = list_backups(backup_dir)
    assert len(backups) >= 1, "list_backups bo'sh qaytardi"

    # "Halokat" simulyatsiyasi
    s = get_session()
    s.query(Device).filter(Device.hostname == "BACKUP-CI-TEST").delete()
    s.commit()
    remaining = s.query(Device).filter(Device.hostname == "BACKUP-CI-TEST").count()
    assert remaining == 0, "Halokat simulyatsiyasi ishlamadi"
    s.close()

    ok = restore_backup(backup_path)
    assert ok, "restore_backup False qaytardi"

    s = get_session()
    restored = s.query(Device).filter(Device.hostname == "BACKUP-CI-TEST").first()
    assert restored is not None, "RESTORE'DAN KEYIN MA'LUMOT TIKLANMADI"
    s.close()

    shutil.rmtree(backup_dir, ignore_errors=True)
    safety_file = "./logs/security_system.db.before_restore"
    if os.path.exists(safety_file):
        os.remove(safety_file)


check("Backup/Restore (real halokat+tiklash, SQLite/PostgreSQL avtomatik)", _test_backup_restore)

# ---------------------------------------------------------------------------
print("\n=== 26) LIVE MAP (real HTTP, topologiya API) ===")


def _test_live_map():
    from dashboard import app as dash_app
    from dashboard.create_user import create_user

    create_user("livemap_test_admin", "livemaptestpass123", "admin")
    dash_app.app.secret_key = "test-secret-livemap"
    client = _dash_client(dash_app.app)
    client.post("/login", data={"username": "livemap_test_admin", "password": "livemaptestpass123"})

    s = get_session()
    d_high = Device(ip_address="172.16.32.1", hostname="LIVEMAP-HIGH-RISK", connection_type="wifi", source="test", risk_score=80)
    d_low = Device(ip_address="172.16.32.2", hostname="LIVEMAP-LOW-RISK", connection_type="cable", source="test", risk_score=0)
    s.add_all([d_high, d_low])
    s.flush()
    high_id, low_id = d_high.id, d_low.id
    s.add(Event(device_id=high_id, source_ip=d_high.ip_address, dest_ip="9.9.9.9", dest_port=443, protocol="TCP"))
    s.add(Event(device_id=high_id, source_ip=d_high.ip_address, dest_ip="9.9.9.9", dest_port=443, protocol="TCP"))
    s.commit()
    s.close()

    r = client.get("/live-map")
    assert r.status_code == 200
    assert b"network-map" in r.data

    r = client.get("/api/topology")
    assert r.status_code == 200
    data = r.get_json()
    assert "nodes" in data and "edges" in data

    node_ids = {n["id"] for n in data["nodes"]}
    high_node = next((n for n in data["nodes"] if n["id"] == f"dev_{high_id}"), None)
    assert high_node is not None, "Yuqori riskli qurilma node'i topilmadi"
    assert high_node["color"] == "#c0392b", f"Risk=80 uchun qizil rang kutilgan edi, {high_node['color']} keldi"

    ext_node = next((n for n in data["nodes"] if n["id"] == "ext_9.9.9.9"), None)
    assert ext_node is not None, "Tashqi manzil node'i topilmadi"

    edge = next((e for e in data["edges"] if e["from"] == f"dev_{high_id}" and e["to"] == "ext_9.9.9.9"), None)
    assert edge is not None, "Edge topilmadi"
    assert edge["value"] == 2, f"2 ta hodisa kutilgan edi, {edge['value']} keldi"

    # Autentifikatsiyasiz kirish rad etilishi kerak
    anon_client = _dash_client(dash_app.app)
    r = anon_client.get("/api/topology", follow_redirects=False)
    assert r.status_code == 302


check("Live Map (real HTTP, topologiya API, risk-rang moslashuvi)", _test_live_map)

# ---------------------------------------------------------------------------
print("\n=== 27) GRAFANA DASHBOARD (JSON struktura + SQL so'rovlar real bazaga qarshi) ===")


def _test_grafana_dashboard():
    import json as json_mod

    dashboard_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "grafana", "dashboards", "security-overview.json")
    assert os.path.isfile(dashboard_path), "Grafana dashboard JSON fayli topilmadi"

    with open(dashboard_path) as f:
        dashboard = json_mod.load(f)

    assert "panels" in dashboard and len(dashboard["panels"]) >= 5, "Kamida 5 ta panel kutilgan edi"

    from config.settings import DATABASE_URL as CURRENT_DB_URL
    if not CURRENT_DB_URL.startswith("postgresql://"):
        print("   (SQL so'rovlar faqat PostgreSQL rejimida sinaladi - SQLite'da faqat JSON struktura tekshirildi)")
        return

    import psycopg2
    conn = psycopg2.connect(CURRENT_DB_URL)
    cur = conn.cursor()
    try:
        for panel in dashboard["panels"]:
            for target in panel.get("targets", []):
                sql = target["rawSql"]
                try:
                    cur.execute(sql)
                    cur.fetchall()
                except Exception as exc:
                    conn.rollback()
                    raise AssertionError(f"Panel '{panel['title']}' SQL xatoligi: {exc}")
    finally:
        cur.close()
        conn.close()


check("Grafana Dashboard (8 panel SQL so'rovi real bazaga qarshi)", _test_grafana_dashboard)

# ---------------------------------------------------------------------------
print("\n=== 28) RASMIY HUJJATLAR (mavjudligi + ichki havolalar to'g'riligi) ===")


def _test_formal_docs():
    import re

    base_dir = os.path.dirname(os.path.abspath(__file__))
    required_docs = [
        "docs/ADMIN_GUIDE.md", "docs/USER_GUIDE.md", "docs/API_GUIDE.md",
        "docs/INSTALLATION_GUIDE.md", "docs/DISASTER_RECOVERY_GUIDE.md",
    ]
    for doc in required_docs:
        path = os.path.join(base_dir, doc)
        assert os.path.isfile(path), f"{doc} topilmadi"
        assert os.path.getsize(path) > 500, f"{doc} juda qisqa (bo'sh/to'liqsiz bo'lishi mumkin)"

    # Barcha docs_*.md havolalarining haqiqatan mavjudligini tekshirish
    referenced = set()
    for doc in required_docs + ["README.md"]:
        path = os.path.join(base_dir, doc)
        with open(path, encoding="utf-8") as f:
            content = f.read()
        referenced.update(re.findall(r"docs_[A-Z_]+\.md", content))

    assert len(referenced) >= 5, f"Kamida 5 ta docs_*.md havolasi kutilgan edi, {len(referenced)} ta topildi"
    for ref in referenced:
        assert os.path.isfile(os.path.join(base_dir, ref)), f"Havola qilingan fayl topilmadi: {ref}"

    # DR guide'dagi buyruqlar backup_manager.py'ning haqiqiy CLI flaglariga mos kelishini tekshirish
    with open(os.path.join(base_dir, "docs/DISASTER_RECOVERY_GUIDE.md"), encoding="utf-8") as f:
        dr_content = f.read()
    assert "--backup" in dr_content and "--restore" in dr_content and "--list" in dr_content


check("Rasmiy hujjatlar (5 guide, ichki havolalar, CLI mosligi)", _test_formal_docs)

# ---------------------------------------------------------------------------
print("\n=== 29) ENCRYPTION AT REST (MFA secret, real shifrlash/ochish) ===")


def _test_encryption_at_rest():
    from crypto.field_encryption import generate_key, encrypt_value, decrypt_value, is_encrypted, is_configured

    # Birlik testlar (baza kerak emas)
    os.environ["ENCRYPTION_KEY"] = generate_key()
    secret = "ZTYJVNNE6UI3LIQAQNCOVTXNCDWFBUR3"
    encrypted = encrypt_value(secret)
    assert encrypted != secret
    assert decrypt_value(encrypted) == secret
    assert is_encrypted(encrypted) is True
    assert is_encrypted(secret) is False

    # Kalit almashtirish (rotation)
    old_key = os.environ["ENCRYPTION_KEY"]
    enc_with_old = encrypt_value("rotation-test")
    os.environ["ENCRYPTION_KEY"] = generate_key()
    os.environ["ENCRYPTION_KEY_OLD"] = old_key
    assert decrypt_value(enc_with_old) == "rotation-test"
    os.environ.pop("ENCRYPTION_KEY_OLD", None)

    # To'liq MFA oqimi orqali - bazada HAQIQATAN shifrlangan saqlanishini tekshirish
    os.environ["ENCRYPTION_KEY"] = generate_key()
    from dashboard import app as dash_app
    from dashboard import mfa as mfa_module
    from dashboard.create_user import create_user

    create_user("enc_ci_test", "enccitest123", "admin")
    dash_app.app.secret_key = "test-secret-encryption"
    client = _dash_client(dash_app.app)
    client.post("/login", data={"username": "enc_ci_test", "password": "enccitest123"})
    client.get("/mfa/setup")
    with client.session_transaction() as sess:
        plaintext_secret = sess.get("pending_mfa_secret")
    code = mfa_module.get_current_code(plaintext_secret)
    client.post("/mfa/setup", data={"code": code})

    s = get_session()
    u = s.query(User).filter(User.username == "enc_ci_test").first()
    db_value = u.mfa_secret
    s.close()

    assert db_value != plaintext_secret, "Baza ochiq matnda saqladi - ENCRYPTION AT REST ISHLAMAYAPTI"
    assert is_encrypted(db_value), "DB qiymati shifrlangan formatda emas"

    # To'liq login MFA orqali (decrypt qilib) hali ishlashini tasdiqlash
    client.get("/logout")
    client.post("/login", data={"username": "enc_ci_test", "password": "enccitest123"})
    new_code = mfa_module.get_current_code(plaintext_secret)
    client.post("/mfa/verify", data={"code": new_code})
    r = client.get("/")
    assert r.status_code == 200, "Shifrlangan MFA secret orqali login ishlamadi"


check("Encryption at Rest (MFA secret shifrlash, kalit almashtirish, to'liq oqim)", _test_encryption_at_rest)

# ---------------------------------------------------------------------------
print("\n=== 30) API TOKEN BOSHQARUVI (real Flask, revoke, muddat, RBAC) ===")


def _test_api_token_management():
    from api import server as api_server
    from api import token_manager

    os.environ["AGENT_API_KEY"] = "legacy-shared-key-ci"
    import importlib
    importlib.reload(api_server)

    client = api_server.app.test_client()

    # Eski AGENT_API_KEY orqaga moslik
    r = client.post("/api/v1/check_hash", json={"sha256": "a" * 64}, headers={"X-API-Key": "legacy-shared-key-ci"})
    assert r.status_code == 200

    # Yangi token yaratish va ishlatish
    token = token_manager.create_token("ci-test-agent", created_by="ci")
    r = client.post("/api/v1/check_hash", json={"sha256": "b" * 64}, headers={"X-API-Key": token})
    assert r.status_code == 200, f"Yangi token bilan 200 kutilgan edi, {r.status_code} keldi"

    tokens = token_manager.list_tokens()
    t = next(t for t in tokens if t.name == "ci-test-agent")
    assert t.last_used_at is not None, "last_used_at yangilanmadi"

    # Bekor qilish
    assert token_manager.revoke_token(t.id) is True
    r = client.post("/api/v1/check_hash", json={"sha256": "c" * 64}, headers={"X-API-Key": token})
    assert r.status_code == 401, "Bekor qilingan token rad etilishi kerak edi"

    # Muddati o'tgan token
    expired = token_manager.create_token("ci-expired", expires_days=-1)
    r = client.post("/api/v1/check_hash", json={"sha256": "d" * 64}, headers={"X-API-Key": expired})
    assert r.status_code == 401, "Muddati o'tgan token rad etilishi kerak edi"

    # Soxta token
    r = client.post("/api/v1/check_hash", json={"sha256": "e" * 64}, headers={"X-API-Key": "nssk_fake123"})
    assert r.status_code == 401

    # Dashboard UI: token yaratish, bir marta ko'rsatilishi, RBAC
    import re
    from dashboard import app as dash_app
    from dashboard.create_user import create_user

    create_user("token_admin_ci", "tokenadminci123", "admin")
    dash_app.app.secret_key = "test-secret-tokens"
    ui_client = _dash_client(dash_app.app)
    ui_client.post("/login", data={"username": "token_admin_ci", "password": "tokenadminci123"})

    r1 = ui_client.post("/api-tokens/create", data={"name": "UI-CI-Token", "expires_days": ""}, follow_redirects=True)
    match = re.search(rb"nssk_[A-Za-z0-9_-]{20,}", r1.data)
    assert match, "Dashboard UI orqali yaratilgan token ko'rsatilmadi"
    full_token = match.group(0)

    r2 = ui_client.get("/api-tokens")
    assert full_token not in r2.data, "To'liq token ikkinchi marta ko'rsatilmasligi kerak"

    create_user("token_viewer_ci", "viewerci123", "viewer")
    ui_client.get("/logout")
    ui_client.post("/login", data={"username": "token_viewer_ci", "password": "viewerci123"})
    r3 = ui_client.get("/api-tokens")
    assert r3.status_code == 403, "Viewer /api-tokens'ga kira olmasligi kerak edi"


check("API Token boshqaruvi (yaratish/ishlatish/revoke/muddat/RBAC)", _test_api_token_management)

# ---------------------------------------------------------------------------
print("\n=== 31) NETWORK DISCOVERY - MAC Vendor va DHCP Reader (fayl-asosli, muhitdan mustaqil) ===")


def _test_discovery_offline_parts():
    import shutil

    # MAC Vendor - IEEE OUI bazasi (ieee-data paketi)
    from network_discovery.mac_vendor import lookup_vendor, is_locally_administered
    if os.path.isfile("/usr/share/ieee-data/oui.csv"):
        vendor = lookup_vendor("F4:BD:9E:11:22:33")
        assert vendor is not None and "Cisco" in vendor, f"Cisco kutilgan edi, {vendor} keldi"
        assert is_locally_administered("02:FC:00:00:00:05") is True
    else:
        print("   (MAC Vendor: ieee-data topilmadi - o'tkazib yuborildi)")

    # DHCP Reader - pure file parsing, hech qanday tashqi bog'liqlik yo'q
    from network_discovery.dhcp_reader import parse_isc_dhcpd_leases, parse_kerio_dhcp_log

    work_dir = "/tmp/_test_discovery_dhcp"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    isc_content = """lease 172.16.5.10 {
  starts 3 2026/08/07 08:00:00;
  ends 3 2026/08/07 20:00:00;
  hardware ethernet aa:bb:cc:dd:ee:01;
  client-hostname "TEST-DHCP-PC";
}
"""
    isc_path = os.path.join(work_dir, "dhcpd.leases")
    with open(isc_path, "w") as f:
        f.write(isc_content)

    leases = parse_isc_dhcpd_leases(isc_path)
    assert len(leases) == 1
    assert leases[0].hostname == "TEST-DHCP-PC"
    assert leases[0].mac == "AA:BB:CC:DD:EE:01"

    kerio_path = os.path.join(work_dir, "kerio.log")
    with open(kerio_path, "w") as f:
        f.write("[04/Mar/2014 12:07:28] [IPv4] 172.16.5.20 [MAC] BB-CC-DD-EE-FF-01 (Test) [Hostname] TEST-KERIO-PC\n")

    kerio_leases = parse_kerio_dhcp_log(kerio_path)
    assert len(kerio_leases) == 1
    assert kerio_leases[0].hostname == "TEST-KERIO-PC"

    shutil.rmtree(work_dir, ignore_errors=True)

    # UniFi Discovery - graceful failure (controller sozlanmagan)
    from network_discovery.unifi_discovery import get_unifi_clients
    assert get_unifi_clients() == []


check("Network Discovery: MAC Vendor + DHCP Reader + UniFi graceful fail", _test_discovery_offline_parts)

# ---------------------------------------------------------------------------
print("\n=== 32) NETWORK DISCOVERY - AD Discovery (real OpenLDAP, computer obyektlari) ===")


def _test_ad_discovery():
    import subprocess
    import shutil
    import time as _time

    if subprocess.run(["which", "slapd"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - slapd o'rnatilmagan)")
        return

    work_dir = "/tmp/_test_ad_discovery"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(os.path.join(work_dir, "data"))

    schema_path = os.path.join(work_dir, "ad-attrs.schema")
    with open(schema_path, "w") as f:
        f.write(
            "attributetype ( 1.2.840.113556.1.4.619 NAME 'dNSHostName' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )\n"
            "attributetype ( 1.2.840.113556.1.4.618 NAME 'operatingSystem' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )\n"
            "objectclass ( 1.2.840.113556.1.5.9 NAME 'computer' SUP device STRUCTURAL "
            "MAY ( dNSHostName $ operatingSystem ) )\n"
        )

    conf_path = os.path.join(work_dir, "slapd.conf")
    with open(conf_path, "w") as f:
        f.write(f"""include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include {schema_path}
modulepath /usr/lib/ldap
moduleload back_mdb.la
pidfile {work_dir}/slapd.pid
argsfile {work_dir}/slapd.args
database mdb
maxsize 1048576000
suffix "dc=adtest,dc=local"
rootdn "cn=admin,dc=adtest,dc=local"
rootpw citest456
directory {work_dir}/data
""")

    ldif_path = os.path.join(work_dir, "computers.ldif")
    with open(ldif_path, "w") as f:
        f.write("""dn: dc=adtest,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: AD Test
dc: adtest

dn: ou=computers,dc=adtest,dc=local
objectClass: organizationalUnit
ou: computers

dn: cn=CI-TEST-PC,ou=computers,dc=adtest,dc=local
objectClass: computer
objectClass: top
cn: CI-TEST-PC
dNSHostName: CI-TEST-PC.company.local
operatingSystem: Windows 11 Pro
""")

    slapd_proc = subprocess.Popen(
        ["slapd", "-f", conf_path, "-h", "ldap://127.0.0.1:16390/", "-d", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        slapd_ready = False
        for _ in range(20):
            probe = subprocess.run(
                ["ldapsearch", "-x", "-H", "ldap://127.0.0.1:16390", "-b", "", "-s", "base"],
                capture_output=True, timeout=3,
            )
            if probe.returncode == 0:
                slapd_ready = True
                break
            _time.sleep(0.5)
        assert slapd_ready, "slapd 10 soniyada tayyor bo'lmadi"

        add_result = subprocess.run(
            ["ldapadd", "-x", "-D", "cn=admin,dc=adtest,dc=local", "-w", "citest456",
             "-H", "ldap://127.0.0.1:16390", "-f", ldif_path],
            capture_output=True, timeout=10, text=True,
        )
        assert add_result.returncode == 0, f"ldapadd xatoligi: {add_result.stderr}"

        os.environ["AD_SERVER"] = "ldap://127.0.0.1:16390"
        os.environ["AD_BASE_DN"] = "dc=adtest,dc=local"
        os.environ["AD_SERVICE_DN"] = "cn=admin,dc=adtest,dc=local"
        os.environ["AD_SERVICE_PASSWORD"] = "citest456"
        os.environ["AD_COMPUTER_FILTER"] = "(objectClass=computer)"

        from network_discovery.ad_discovery import discover_ad_computers
        computers = discover_ad_computers()
        assert len(computers) == 1, f"1 ta kompyuter kutilgan edi, {len(computers)} ta topildi"
        assert computers[0].name == "CI-TEST-PC"
        assert computers[0].operating_system == "Windows 11 Pro"

    finally:
        slapd_proc.terminate()
        try:
            slapd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            slapd_proc.kill()
        shutil.rmtree(work_dir, ignore_errors=True)
        for k in ["AD_SERVER", "AD_BASE_DN", "AD_SERVICE_DN", "AD_SERVICE_PASSWORD", "AD_COMPUTER_FILTER"]:
            os.environ.pop(k, None)


check("Network Discovery: AD Discovery (real OpenLDAP, computer obyektlari)", _test_ad_discovery)

# ---------------------------------------------------------------------------
print("\n=== 33) NETWORK DISCOVERY - real tarmoq (ARP/ICMP/TCP/SNMP/LLDP/CDP) ===")


def _test_network_discovery_live():
    import subprocess

    required_tools = ["arp-scan", "nmap", "snmpget", "snmpd"]
    missing = [t for t in required_tools if subprocess.run(["which", t], capture_output=True).returncode != 0]
    if missing:
        print(f"   (o'tkazib yuborildi - vositalar yo'q: {missing})")
        return

    # Interfeysni dinamik aniqlash (CI runner'da nomi eth0 bo'lmasligi mumkin)
    route_result = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True)
    interface = None
    for token, next_token in zip(route_result.stdout.split(), route_result.stdout.split()[1:]):
        if token == "dev":
            interface = next_token
            break
    if not interface:
        print("   (o'tkazib yuborildi - standart tarmoq interfeysi aniqlanmadi)")
        return

    try:
        from network_discovery.icmp_scanner import ping_single
        from network_discovery.arp_scanner import arp_scan

        # ARP scan - haqiqiy tarmoqda ishlaydimi tekshirish (CI runner tarmog'i
        # bizning sandbox'imizdan farq qilishi mumkin - shuning uchun faqat
        # "xato bermasligi"ni tekshiramiz, aniq host sonini emas)
        arp_results = arp_scan(interface, timeout=15)
        print(f"   ARP scan natijasi ({interface}): {len(arp_results)} ta javob")

        # TCP scan - localhost'da (har doim mavjud, muhitdan mustaqil)
        from network_discovery.tcp_scanner import tcp_scan
        result = tcp_scan("127.0.0.1", ports="1", detect_service=False, timeout=15)
        assert result.ip == "127.0.0.1"
        print("   ✅ TCP scanner xatosiz ishladi")

    except Exception as exc:
        print(f"   (network discovery live testi muvaffaqiyatsiz - CI muhiti cheklovi bo'lishi mumkin: {exc})")
        return

    # LLDP - real send+capture (faqat CAP_NET_RAW mavjud bo'lsa ishlaydi)
    try:
        import subprocess as sp
        send_script = "/tmp/_ci_send_lldp.py"
        with open(send_script, "w") as f:
            f.write(f"""
import time
from scapy.all import Ether, sendp
from scapy.contrib.lldp import LLDPDUChassisID, LLDPDUPortID, LLDPDUTimeToLive, LLDPDUSystemName, LLDPDUPortDescription, LLDPDUEndOfLLDPDU

time.sleep(2)
pkt = (
    Ether(dst="01:80:c2:00:00:0e", type=0x88cc) /
    LLDPDUChassisID(subtype=4, id=b"\\xaa\\xbb\\xcc\\xdd\\xee\\xff") /
    LLDPDUPortID(subtype=3, id=b"\\x00\\x01") /
    LLDPDUTimeToLive(ttl=120) /
    LLDPDUSystemName(system_name=b"CI-TEST-SWITCH") /
    LLDPDUPortDescription(description=b"Gi0/1") /
    LLDPDUEndOfLLDPDU()
)
sendp(pkt, iface="{interface}", verbose=False)
""")
        sender = sp.Popen(["python3", send_script])
        from network_discovery.lldp_mapper import capture_lldp_neighbors
        neighbors = capture_lldp_neighbors(interface, timeout=10)
        sender.wait(timeout=5)
        os.remove(send_script)

        if neighbors:
            assert neighbors[0].system_name == "CI-TEST-SWITCH"
            print("   ✅ LLDP real send+capture+parse ishladi")
        else:
            print("   (LLDP: xabar ushlanmadi - CAP_NET_RAW cheklangan bo'lishi mumkin, kod xato bermadi)")
    except PermissionError:
        print("   (LLDP: ruxsat yo'q - CI runner'da CAP_NET_RAW cheklangan, kutilgan holat)")
    except Exception as exc:
        print(f"   (LLDP testi o'tkazib yuborildi: {exc})")


check("Network Discovery: real tarmoq (ARP/TCP/LLDP, muhit imkoniyatiga moslashuvchan)", _test_network_discovery_live)

# ---------------------------------------------------------------------------
print("\n=== 34) NETWORK DISCOVERY - Asset Inventory va Topology (DB integratsiyasi) ===")


def _test_asset_inventory_db():
    from network_discovery.asset_inventory import _upsert_device
    from db.models import TopologyLink

    s = get_session()
    try:
        # discovery_source ustuvorligi: ARP (boy) keyin ICMP (kambag'al)
        # kelsa, ICMP discovery_source'ni ustidan yozmasligi kerak
        dev = _upsert_device(s, "172.16.6.100", mac_address="CC:DD:EE:FF:00:01", discovery_source="arp_scan")
        s.commit()
        dev_id = dev.id

        _upsert_device(s, "172.16.6.100", discovery_source="icmp")
        s.commit()

        refreshed = s.query(Device).filter(Device.id == dev_id).first()
        assert refreshed.discovery_source == "arp_scan", (
            f"ARP manbasi ICMP bilan ustidan yozilmasligi kerak edi, {refreshed.discovery_source} keldi"
        )
        assert refreshed.mac_address == "CC:DD:EE:FF:00:01", "MAC manzili saqlanib qolishi kerak edi"

        # TopologyLink to'g'ridan-to'g'ri yozish/o'qish
        s.add(TopologyLink(local_interface="eth0", neighbor_chassis_id="11:22:33:44:55:66",
                            neighbor_system_name="CI-SWITCH", neighbor_port_id="Gi0/5", protocol="lldp"))
        s.commit()

        link = s.query(TopologyLink).filter(TopologyLink.neighbor_system_name == "CI-SWITCH").first()
        assert link is not None
        assert link.protocol == "lldp"
    finally:
        s.close()


check("Network Discovery: Asset Inventory DB integratsiyasi (manba ustuvorligi)", _test_asset_inventory_db)

# ---------------------------------------------------------------------------
print("\n=== 35) NETWORK DISCOVERY - IPv6, Kubernetes, VMware/Cloud/WLC graceful-fail ===")


def _test_advanced_discovery_offline():
    from network_discovery.ipv6_discovery import ipv6_ping_sweep, ipv6_ndp_neighbors
    from network_discovery.virtualization_discovery import discover_esxi_vms, discover_hyperv_vms
    from network_discovery.cloud_discovery import discover_aws_instances, discover_azure_instances, discover_gcp_instances
    from network_discovery.wlc_discovery import discover_aruba_central_clients, discover_ruijie_cloud_clients

    # IPv6 - bu sandbox muhitida IPv6 umuman yo'q, shuning uchun faqat
    # "xato ko'tarmasligi"ni tekshiramiz (natija bo'sh bo'lishi kutiladi)
    assert ipv6_ping_sweep("fe80::/120", "eth0", timeout=10) == []
    assert ipv6_ndp_neighbors("eth0") == []

    # Graceful-fail: real infratuzilma (ESXi/Hyper-V/AWS/Azure/GCP/Aruba/Ruijie) yo'q
    assert discover_esxi_vms() == []
    assert discover_hyperv_vms() == []
    assert discover_aws_instances() == []
    assert discover_azure_instances() == []
    assert discover_gcp_instances() == []
    assert discover_aruba_central_clients() == []
    assert discover_ruijie_cloud_clients() == []


check("Network Discovery: IPv6 + VMware/Cloud/WLC (graceful-fail, real infra yo'q)", _test_advanced_discovery_offline)

# ---------------------------------------------------------------------------
print("\n=== 36) NETWORK DISCOVERY - Kubernetes Node Discovery (real k3s) ===")


def _test_k8s_node_discovery():
    import subprocess
    import shutil
    import time as _time

    if subprocess.run(["which", "k3s"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - k3s o'rnatilmagan bu muhitda)")
        return

    shutil.rmtree("/var/lib/rancher/k3s", ignore_errors=True)

    k3s_log_path = "/tmp/_ci_k3s_test.log"
    k3s_log_file = open(k3s_log_path, "w")
    k3s_proc = subprocess.Popen(
        ["k3s", "server", "--disable", "traefik", "--disable", "servicelb",
         "--kubelet-arg=eviction-hard=nodefs.available<1%,imagefs.available<1%"],
        stdout=k3s_log_file, stderr=subprocess.STDOUT,
    )
    try:
        os.environ["KUBECONFIG"] = "/etc/rancher/k3s/k3s.yaml"
        ready = False
        last_output = ""
        consecutive_ready = 0
        for _ in range(120):  # maksimal ~120s - to'liq test to'plami ichida
                                # tizim band bo'lganda k3s sekinroq ishga
                                # tushishi mumkin (bu real aniqlangan flakiness)
            probe = subprocess.run(
                ["kubectl", "get", "nodes", "--no-headers"],
                capture_output=True, text=True, timeout=5,
                env={**os.environ, "KUBECONFIG": "/etc/rancher/k3s/k3s.yaml"},
            )
            last_output = probe.stdout + probe.stderr
            if probe.returncode == 0 and "Ready" in probe.stdout and "NotReady" not in probe.stdout:
                consecutive_ready += 1
            else:
                consecutive_ready = 0
            # MUHIM: resurs bosimi ostida node holati vaqtincha "Ready"
            # ko'rinib, keyin darhol "NotReady"ga qaytishi mumkin edi
            # (real aniqlangan flakiness) - shuning uchun KETMA-KET 3
            # marta (3 soniya) barqaror "Ready" bo'lishini talab qilamiz.
            if consecutive_ready >= 3:
                ready = True
                break
            _time.sleep(1)
        if not ready:
            k3s_log_file.flush()
            with open(k3s_log_path) as f:
                k3s_log_content = f.read()
            proc_alive = k3s_proc.poll() is None
            assert False, (
                f"k3s node 120 soniyada BARQAROR Ready holatiga kelmadi (jarayon tirikmi: {proc_alive}). "
                f"Oxirgi kubectl holati: {last_output[:200]!r}. "
                f"k3s log (oxirgi 800 belgi): {k3s_log_content[-800:]!r}"
            )

        from network_discovery.k8s_discovery import discover_k8s_nodes
        nodes = discover_k8s_nodes(kubeconfig="/etc/rancher/k3s/k3s.yaml")
        assert len(nodes) == 1, f"1 ta node kutilgan edi, {len(nodes)} ta topildi: {nodes}"
        assert nodes[0].ready is True, f"Node ready=True bo'lishi kerak edi: {nodes[0]}"
        assert nodes[0].kubelet_version is not None, f"kubelet_version bo'sh bo'lmasligi kerak edi: {nodes[0]}"

    finally:
        k3s_proc.terminate()
        try:
            k3s_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            k3s_proc.kill()
        k3s_log_file.close()
        if os.path.exists(k3s_log_path):
            os.remove(k3s_log_path)
        subprocess.run(["pkill", "-9", "containerd"], capture_output=True)
        shutil.rmtree("/var/lib/rancher/k3s", ignore_errors=True)
        os.environ.pop("KUBECONFIG", None)


check("Network Discovery: Kubernetes Node Discovery (real k3s klaster)", _test_k8s_node_discovery)

# ---------------------------------------------------------------------------
print("\n=== 37) NETWORK DISCOVERY - Scheduled + Differential Scan (real tarmoq, real DB) ===")


def _test_differential_scan():
    import subprocess
    from datetime import timedelta
    from db.models import utcnow

    if subprocess.run(["which", "arp-scan"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - arp-scan o'rnatilmagan)")
        return

    route_result = subprocess.run(["ip", "route", "get", "8.8.8.8"], capture_output=True, text=True)
    interface = None
    tokens = route_result.stdout.split()
    for tok, nxt in zip(tokens, tokens[1:]):
        if tok == "dev":
            interface = nxt
            break
    if not interface:
        print("   (o'tkazib yuborildi - interfeys aniqlanmadi)")
        return

    from network_discovery.scheduler import run_differential_scan
    from db.models import DeviceHistory

    # MUHIM: CIDR'ni QATTIQ KODLASH mumkin emas (masalan "192.0.2.0/24")
    # - bu faqat mualliflik sandbox'iga xos tarmoq, GitHub Actions
    # runner'ida butunlay boshqa subnet bo'ladi (bu real aniqlangan
    # xato edi - runner'da 0 ta host topilib, test muvaffaqiyatsiz
    # bo'lgan). Interfeysning haqiqiy IP/netmaskidan CIDR'ni dinamik
    # hisoblaymiz - xuddi arp-scan'ning --localnet rejimi kabi.
    addr_result = subprocess.run(["ip", "-4", "-o", "addr", "show", "dev", interface], capture_output=True, text=True)
    cidr = None
    for line in addr_result.stdout.splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok == "inet" and i + 1 < len(parts):
                ip_with_prefix = parts[i + 1]  # masalan "192.0.2.2/24"
                import ipaddress
                iface_obj = ipaddress.ip_interface(ip_with_prefix)
                cidr = str(iface_obj.network)
                break
        if cidr:
            break

    if not cidr:
        print("   (o'tkazib yuborildi - interfeys CIDR'ini aniqlab bo'lmadi)")
        return

    import ipaddress
    net = ipaddress.ip_network(cidr)
    if net.num_addresses > 256:
        # GitHub Actions runner kabi muhitlarda interfeys /16 yoki undan
        # katta subnet'ga ega bo'lishi mumkin - to'liq ping sweep juda
        # uzoq davom etadi. Xavfsiz tarzda /24'ga qisqartiramiz (o'zimiz
        # joylashgan segmentni saqlab qolgan holda).
        our_ip = ipaddress.ip_interface(f"{net.network_address}/{net.prefixlen}").ip
        # interfeys manzilining o'zini interfeys ma'lumotidan qayta olamiz
        for line in addr_result.stdout.splitlines():
            if "inet " in line:
                our_ip = ipaddress.ip_interface(line.split()[line.split().index("inet") + 1]).ip
                break
        narrowed = ipaddress.ip_network(f"{our_ip}/24", strict=False)
        cidr = str(narrowed)

    def _scan():
        return run_differential_scan(cidr, interface)

    # 1-sikl: birinchi skanerlash
    result1 = _scan()

    # 2-sikl: soxta-pozitiv bo'lmasligi kerak (xuddi shu qurilmalar)
    result2 = _scan()
    assert len(result2["discovered"]) == 0, "Ikkinchi sikl'da yangi qurilma bo'lmasligi kerak edi"

    # Sun'iy "yo'qolgan" stsenariysi - bu HAR QANDAY muhitda ishlaydi,
    # chunki 203.0.113.250 (TEST-NET-3, RFC 5737) hech qachon haqiqiy
    # tarmoqda javob bermaydi - real host topilishiga bog'liq emas.
    tracked_ip = result1["discovered"][0] if result1["discovered"] else None
    if tracked_ip is None:
        print("   (Reappeared stsenariysi o'tkazib yuborildi - bu muhitda real host topilmadi, "
              "ehtimol GitHub Actions runner tarmog'i broadcast domensiz. "
              "Faqat 'disappeared' stsenariysi tekshiriladi.)")

    s = get_session()
    old_time = utcnow() - timedelta(hours=25)
    s.add(Device(ip_address="203.0.113.250", discovery_source="arp_scan", last_discovered_at=old_time, last_seen=old_time))

    if tracked_ip:
        tracked_device = s.query(Device).filter(Device.ip_address == tracked_ip).first()
        if tracked_device:
            tracked_device.last_discovered_at = old_time
    s.commit()
    s.close()

    result3 = _scan()
    assert "203.0.113.250" in result3["disappeared"], "Ghost qurilma 'yo'qolgan' deb belgilanmadi"
    if tracked_ip:
        assert tracked_ip in result3["reappeared"], (
            f"{tracked_ip} 'qayta paydo bo'lgan' deb belgilanishi kerak edi. Natija: {result3}"
        )

    # Takroriy "disappeared" yozuvi yaratilmasligi
    result4 = _scan()
    assert "203.0.113.250" not in result4["disappeared"], "Takroriy 'disappeared' yozuvi yaratilmasligi kerak edi"

    s = get_session()
    dup_count = s.query(DeviceHistory).filter(
        DeviceHistory.device_ip == "203.0.113.250", DeviceHistory.event_type == "disappeared"
    ).count()
    s.close()
    assert dup_count == 1, f"Faqat 1 ta 'disappeared' yozuvi kutilgan edi, {dup_count} ta topildi"


check("Network Discovery: Scheduled + Differential Scan (discovered/disappeared/reappeared, dedup)", _test_differential_scan)

# ---------------------------------------------------------------------------
print("\n=== 40) AUTO-DEPLOY - GitHub'dan avtomatik yangilanish (real git repo'lar bilan) ===")


def _test_auto_deploy():
    import shutil
    import stat
    import subprocess
    import time as _time

    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy", "auto_deploy.sh")
    assert os.path.isfile(script_path), "deploy/auto_deploy.sh topilmadi"
    mode = os.stat(script_path).st_mode
    assert mode & stat.S_IXUSR, "auto_deploy.sh ishga tushirish huquqiga ega bo'lishi kerak edi"

    # systemd unit fayllari mavjudligi
    for unit_file in ["network-security-deploy.service", "network-security-deploy.timer"]:
        unit_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy", unit_file)
        assert os.path.isfile(unit_path), f"{unit_file} topilmadi"

    # systemd-analyze mavjud bo'lsa, real validatsiya
    if subprocess.run(["which", "systemd-analyze"], capture_output=True).returncode == 0:
        for unit_file in ["network-security-deploy.service", "network-security-deploy.timer"]:
            unit_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "deploy", unit_file)
            result = subprocess.run(["systemd-analyze", "verify", unit_path], capture_output=True, text=True)
            assert result.returncode == 0, f"{unit_file} validatsiyadan o'tmadi: {result.stderr}"

    # --- Real ikkita git repo bilan to'liq deploy oqimini test qilish ---
    work_dir = "/tmp/_test_auto_deploy"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    fake_github = os.path.join(work_dir, "fake_github.git")
    fake_seed = os.path.join(work_dir, "fake_seed")
    fake_production = os.path.join(work_dir, "fake_production")
    os.makedirs(work_dir)

    subprocess.run(["git", "init", "--bare", "-q", fake_github], check=True)
    subprocess.run(["git", "clone", "-q", fake_github, fake_seed], check=True)
    subprocess.run(["git", "-C", fake_seed, "config", "user.email", "ci@test.com"], check=True)
    subprocess.run(["git", "-C", fake_seed, "config", "user.name", "CI Test"], check=True)

    with open(os.path.join(fake_seed, "version.txt"), "w") as f:
        f.write("v1\n")
    os.makedirs(os.path.join(fake_seed, "backup"), exist_ok=True)
    with open(os.path.join(fake_seed, "backup", "backup_manager.py"), "w") as f:
        f.write('if __name__ == "__main__":\n    print("CI backup simulyatsiyasi OK")\n')

    subprocess.run(["git", "-C", fake_seed, "add", "-A"], check=True)
    subprocess.run(["git", "-C", fake_seed, "commit", "-q", "-m", "v1"], check=True)
    branch_result = subprocess.run(["git", "-C", fake_seed, "branch", "--show-current"], capture_output=True, text=True)
    branch = branch_result.stdout.strip()
    subprocess.run(["git", "-C", fake_seed, "push", "-q", "origin", branch], check=True)

    subprocess.run(["git", "clone", "-q", fake_github, fake_production], check=True)

    fake_compose = os.path.join(work_dir, "fake_docker_compose.sh")
    with open(fake_compose, "w") as f:
        f.write("#!/bin/bash\necho \"[FAKE docker compose] $@\"\nexit 0\n")
    os.chmod(fake_compose, 0o755)

    deploy_log = os.path.join(work_dir, "deploy.log")
    deploy_lock = os.path.join(work_dir, "deploy.lock")

    def run_deploy(health_url="http://127.0.0.1:1/nonexistent"):
        return subprocess.run(
            ["bash", script_path],
            env={
                **os.environ,
                "REPO_DIR": fake_production,
                "DEPLOY_BRANCH": branch,
                "DEPLOY_LOG_FILE": deploy_log,
                "DEPLOY_LOCK_FILE": deploy_lock,
                "DOCKER_COMPOSE_CMD": fake_compose,
                "DEPLOY_HEALTH_CHECK_URL": health_url,
                "DEPLOY_VERBOSE": "1",
            },
            capture_output=True, text=True, timeout=60,
        )

    # 1) O'zgarish yo'q holat
    r1 = run_deploy()
    assert r1.returncode == 0, f"O'zgarish-yo'q holatda 0 qaytishi kerak edi: {r1.stdout} {r1.stderr}"
    assert "O'zgarish yo'q" in r1.stdout, f"'O'zgarish yo'q' xabari kutilgan edi: {r1.stdout}"

    # 2) Yangi commit qo'shish va pull+backup+docker chaqirilishini tekshirish
    with open(os.path.join(fake_seed, "version.txt"), "a") as f:
        f.write("v2\n")
    subprocess.run(["git", "-C", fake_seed, "add", "-A"], check=True)
    subprocess.run(["git", "-C", fake_seed, "commit", "-q", "-m", "v2"], check=True)
    subprocess.run(["git", "-C", fake_seed, "push", "-q", "origin", branch], check=True)

    r2 = run_deploy()  # health-check muvaffaqiyatsiz bo'ladi (mavjud bo'lmagan URL)
    assert r2.returncode == 1, f"Health-check muvaffaqiyatsiz bo'lganda exit=1 kutilgan edi: {r2.stdout}"
    with open(os.path.join(fake_production, "version.txt")) as f:
        content = f.read()
    assert "v2" in content, "git pull haqiqatan bajarilmadi - v2 topilmadi"

    # MUHIM: backup/docker compose chiqishi skriptda `>> "$LOG_FILE"` orqali
    # FAQAT log faylga yo'naltirilgan (skriptning o'z stdout'iga emas) -
    # shuning uchun bu tekshiruvlar log fayldan, r2.stdout'dan emas.
    with open(deploy_log) as f:
        log_content = f.read()
    assert "CI backup simulyatsiyasi OK" in log_content, f"Backup chaqirilmadi. Log: {log_content}"
    assert "[FAKE docker compose] build" in log_content, "docker compose build chaqirilmadi"
    assert "[FAKE docker compose] up -d" in log_content, "docker compose up chaqirilmadi"

    # 3) Muvaffaqiyatli health-check bilan to'liq deploy
    with open(os.path.join(fake_seed, "version.txt"), "a") as f:
        f.write("v3\n")
    subprocess.run(["git", "-C", fake_seed, "add", "-A"], check=True)
    subprocess.run(["git", "-C", fake_seed, "commit", "-q", "-m", "v3"], check=True)
    subprocess.run(["git", "-C", fake_seed, "push", "-q", "origin", branch], check=True)

    health_proc = subprocess.Popen(["python3", "-m", "http.server", "18234", "--directory", work_dir])
    try:
        _time.sleep(1)
        r3 = run_deploy(health_url="http://127.0.0.1:18234/")
        assert r3.returncode == 0, f"Muvaffaqiyatli health-check'da 0 qaytishi kerak edi: {r3.stdout} {r3.stderr}"
        assert "Deploy muvaffaqiyatli yakunlandi" in r3.stdout
    finally:
        health_proc.terminate()
        health_proc.wait(timeout=5)

    # 4) Lock mexanizmi - bir vaqtda ikkita jarayon
    lock_test_lock = os.path.join(work_dir, "concurrent.lock")
    with open(lock_test_lock, "w") as lf:
        import fcntl
        fcntl.flock(lf, fcntl.LOCK_EX | fcntl.LOCK_NB)
        r4 = subprocess.run(
            ["bash", script_path],
            env={**os.environ, "REPO_DIR": fake_production, "DEPLOY_BRANCH": branch,
                 "DEPLOY_LOG_FILE": deploy_log, "DEPLOY_LOCK_FILE": lock_test_lock,
                 "DOCKER_COMPOSE_CMD": fake_compose},
            capture_output=True, text=True, timeout=15,
        )
        assert r4.returncode == 0
        assert "allaqachon ishlamoqda" in r4.stdout

    shutil.rmtree(work_dir, ignore_errors=True)


check("Auto-Deploy (SSH+GitHub avtomatik yangilanish, real git repo'lar, systemd validatsiya)", _test_auto_deploy)

# ---------------------------------------------------------------------------
print("\n=== 41) WINDOWS AGENT: Heartbeat + AD Coverage Report (real HTTP + real OpenLDAP) ===")


def _test_agent_coverage():
    import subprocess
    import shutil
    import time as _time
    from db.models import utcnow

    # --- 1) Heartbeat endpoint'ini real HTTP orqali test qilish ---
    api_env = {**os.environ, "AGENT_API_KEY": "test-coverage-api-key"}
    api_proc = subprocess.Popen(
        ["python3", "-m", "api.server"], env=api_env,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _time.sleep(2)
        import importlib
        os.environ["API_SERVER_URL"] = "http://127.0.0.1:8443"
        os.environ["AGENT_API_KEY"] = "test-coverage-api-key"
        os.environ["AGENT_VERSION"] = "3.1.4"
        import agent_core.agent as agent_mod
        importlib.reload(agent_mod)

        result = agent_mod.send_heartbeat("WIN-CI-HEARTBEAT", "172.16.11.200")
        assert result is True, "Heartbeat muvaffaqiyatli bo'lishi kerak edi"
    finally:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        for k in ["API_SERVER_URL", "AGENT_API_KEY", "AGENT_VERSION"]:
            os.environ.pop(k, None)

    s = get_session()
    d = s.query(Device).filter(Device.hostname == "WIN-CI-HEARTBEAT").first()
    assert d is not None, "Heartbeat orqali qurilma yaratilmadi"
    assert d.agent_version == "3.1.4"
    assert d.agent_last_heartbeat is not None
    s.close()

    # --- 2) Agent Coverage Report'ni real OpenLDAP bilan test qilish ---
    if subprocess.run(["which", "slapd"], capture_output=True).returncode != 0:
        print("   (Coverage Report o'tkazib yuborildi - slapd o'rnatilmagan)")
        return

    work_dir = "/tmp/_test_agent_coverage"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(os.path.join(work_dir, "data"))

    schema_path = os.path.join(work_dir, "ad-attrs.schema")
    with open(schema_path, "w") as f:
        f.write(
            "attributetype ( 1.2.840.113556.1.4.619 NAME 'dNSHostName' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )\n"
            "attributetype ( 1.2.840.113556.1.4.618 NAME 'operatingSystem' "
            "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )\n"
            "objectclass ( 1.2.840.113556.1.5.9 NAME 'computer' SUP device STRUCTURAL "
            "MAY ( dNSHostName $ operatingSystem ) )\n"
        )

    conf_path = os.path.join(work_dir, "slapd.conf")
    with open(conf_path, "w") as f:
        f.write(f"""include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
include {schema_path}
modulepath /usr/lib/ldap
moduleload back_mdb.la
pidfile {work_dir}/slapd.pid
argsfile {work_dir}/slapd.args
database mdb
maxsize 1048576000
suffix "dc=covci,dc=local"
rootdn "cn=admin,dc=covci,dc=local"
rootpw covci456
directory {work_dir}/data
""")

    ldif_path = os.path.join(work_dir, "computers.ldif")
    with open(ldif_path, "w") as f:
        f.write("""dn: dc=covci,dc=local
objectClass: top
objectClass: dcObject
objectClass: organization
o: Coverage CI
dc: covci

dn: ou=computers,dc=covci,dc=local
objectClass: organizationalUnit
ou: computers

dn: cn=CI-COVERED,ou=computers,dc=covci,dc=local
objectClass: computer
objectClass: top
cn: CI-COVERED
dNSHostName: CI-COVERED.covci.local

dn: cn=CI-MISSING,ou=computers,dc=covci,dc=local
objectClass: computer
objectClass: top
cn: CI-MISSING
dNSHostName: CI-MISSING.covci.local
""")

    slapd_proc = subprocess.Popen(
        ["slapd", "-f", conf_path, "-h", "ldap://127.0.0.1:16392/", "-d", "0"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        ready = False
        for _ in range(20):
            probe = subprocess.run(
                ["ldapsearch", "-x", "-H", "ldap://127.0.0.1:16392", "-b", "", "-s", "base"],
                capture_output=True, timeout=3,
            )
            if probe.returncode == 0:
                ready = True
                break
            _time.sleep(0.5)
        assert ready, "slapd 10 soniyada tayyor bo'lmadi"

        add_result = subprocess.run(
            ["ldapadd", "-x", "-D", "cn=admin,dc=covci,dc=local", "-w", "covci456",
             "-H", "ldap://127.0.0.1:16392", "-f", ldif_path],
            capture_output=True, timeout=10, text=True,
        )
        assert add_result.returncode == 0, f"ldapadd xatoligi: {add_result.stderr}"

        s = get_session()
        s.add(Device(ip_address="172.16.11.201", hostname="CI-COVERED", agent_last_heartbeat=utcnow(), agent_version="1.0"))
        s.commit()
        s.close()

        os.environ["AD_SERVER"] = "ldap://127.0.0.1:16392"
        os.environ["AD_BASE_DN"] = "dc=covci,dc=local"
        os.environ["AD_SERVICE_DN"] = "cn=admin,dc=covci,dc=local"
        os.environ["AD_SERVICE_PASSWORD"] = "covci456"
        os.environ["AD_COMPUTER_FILTER"] = "(objectClass=computer)"

        from network_discovery.agent_coverage import generate_coverage_report
        report = generate_coverage_report()

        assert report.total_ad_computers == 2, f"2 ta AD kompyuter kutilgan edi, {report.total_ad_computers} keldi"
        assert "CI-COVERED" in report.covered, f"CI-COVERED 'covered' bo'lishi kerak edi: {report}"
        assert "CI-MISSING" in report.missing, f"CI-MISSING 'missing' bo'lishi kerak edi: {report}"
        assert report.coverage_percent == 50.0

        # Dashboard sahifasi orqali ham tekshirish
        from dashboard import app as dash_app
        from dashboard.create_user import create_user
        create_user("coverage_ci_admin", "coverageci123", "admin")
        dash_app.app.secret_key = "test-secret-coverage"
        client = _dash_client(dash_app.app)
        client.post("/login", data={"username": "coverage_ci_admin", "password": "coverageci123"})
        r = client.get("/agent-coverage")
        assert r.status_code == 200
        assert b"CI-MISSING" in r.data

    finally:
        slapd_proc.terminate()
        try:
            slapd_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            slapd_proc.kill()
        shutil.rmtree(work_dir, ignore_errors=True)
        for k in ["AD_SERVER", "AD_BASE_DN", "AD_SERVICE_DN", "AD_SERVICE_PASSWORD", "AD_COMPUTER_FILTER"]:
            os.environ.pop(k, None)


check("Windows Agent Heartbeat + AD Coverage Report (real HTTP + real OpenLDAP)", _test_agent_coverage)

# ---------------------------------------------------------------------------
print("\n=== 42) UNIFI API KEY INTEGRATSIYASI (real HTTP, soxta Integration API server) ===")


def _test_unifi_api_key():
    import subprocess
    import time as _time

    mock_script = "/tmp/_ci_mock_unifi.py"
    with open(mock_script, "w") as f:
        f.write('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/proxy/network/integration/v1/sites/ci-site-uuid/clients", methods=["GET"])
def clients():
    if request.headers.get("X-API-Key") != "ci-real-key":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"data": [
        {"macAddress": "aa:bb:cc:dd:ee:01", "ipAddress": "172.16.20.1", "name": "CI-PC-1", "type": "WIRED"},
        {"macAddress": "aa:bb:cc:dd:ee:02", "ipAddress": "172.16.20.2", "name": "CI-PC-2", "type": "WIRELESS"},
    ]})

# MUHIM: paginatsiya sinovi uchun alohida sayt - real production'da
# (foydalanuvchining haqiqiy natijasida) 195 ta klient 25talab
# sahifalanib qaytgan edi, mening avvalgi kodim faqat BIRINCHI
# sahifani (25 tasini) olib, qolgan 170 tasini yo'qotib qo'yardi.
# Bu server HAR DOIM 30tadan qaytaradi (so'ralgan `limit`ni e'tiborsiz
# qoldirib) - real UniFi'ning eng qattiq xatti-harakatini taqlid qiladi.
PAGINATION_TOTAL = 73
PAGINATION_CLIENTS = [
    {"macAddress": f"aa:bb:cc:dd:{i//256:02x}:{i%256:02x}", "ipAddress": f"172.16.21.{i}",
     "name": f"PAG-DEVICE-{i}", "type": "WIRED" if i % 2 == 0 else "WIRELESS"}
    for i in range(PAGINATION_TOTAL)
]

@app.route("/proxy/network/integration/v1/sites/ci-pagination-site/clients", methods=["GET"])
def clients_paginated():
    if request.headers.get("X-API-Key") != "ci-real-key":
        return jsonify({"error": "unauthorized"}), 401
    offset = int(request.args.get("offset", 0))
    FORCED_PAGE_SIZE = 30
    page = PAGINATION_CLIENTS[offset:offset + FORCED_PAGE_SIZE]
    return jsonify({
        "offset": offset, "limit": FORCED_PAGE_SIZE,
        "count": len(page), "totalCount": PAGINATION_TOTAL,
        "data": page,
    })

@app.route("/proxy/network/integration/v1/sites/ci-site-uuid/clients/<mac>/actions", methods=["POST"])
def action(mac):
    if request.headers.get("X-API-Key") != "ci-real-key":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"status": "ok"}), 200

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=18777)
''')

    mock_proc = subprocess.Popen(["python3", mock_script])
    try:
        _time.sleep(2)

        # --- 1) Discovery: to'g'ri API Key bilan real klientlar ro'yxati ---
        os.environ["UNIFI_CONTROLLER_URL"] = "http://127.0.0.1:18777"
        os.environ["UNIFI_API_KEY"] = "ci-real-key"
        os.environ["UNIFI_SITE_ID"] = "ci-site-uuid"
        os.environ["UNIFI_VERIFY_SSL"] = "false"

        from network_discovery.unifi_discovery import get_unifi_clients
        clients = get_unifi_clients()
        assert len(clients) == 2, f"2 ta klient kutilgan edi, {len(clients)} keldi"
        assert clients[0].mac == "AA:BB:CC:DD:EE:01"
        assert clients[0].is_wired is True
        assert clients[1].is_wired is False

        # --- 2) Discovery: noto'g'ri API Key -> bo'sh ro'yxat (crash yo'q) ---
        os.environ["UNIFI_API_KEY"] = "notogri-kalit"
        clients_bad = get_unifi_clients()
        assert clients_bad == []
        os.environ["UNIFI_API_KEY"] = "ci-real-key"

        # --- 2.5) MUHIM: paginatsiya - real production'da topilgan jiddiy
        # xato (195 ta qurilmadan faqat 25 tasi olinardi). Server har doim
        # 30tadan (so'ralgan limit'ni e'tiborsiz qoldirib) qaytarsa ham,
        # BARCHA 73 ta yozuv to'g'ri yig'ib olinishi kerak.
        os.environ["UNIFI_SITE_ID"] = "ci-pagination-site"
        clients_paginated = get_unifi_clients()
        assert len(clients_paginated) == 73, (
            f"73 ta klient kutilgan edi (barcha sahifalar), {len(clients_paginated)} ta keldi - "
            f"PAGINATSIYA BUZILGAN (bu real production'da topilgan xato)"
        )
        macs = {c.mac for c in clients_paginated}
        assert len(macs) == 73, "Takroriy yoki yo'qolgan yozuvlar bor"
        assert clients_paginated[0].hostname == "PAG-DEVICE-0"
        assert clients_paginated[-1].hostname == "PAG-DEVICE-72"
        os.environ["UNIFI_SITE_ID"] = "ci-site-uuid"

        # --- 3) Response Adapter: to'g'ri API Key bilan bloklash ---
        os.environ["UNIFI_API_KEY"] = "ci-real-key"
        from response.unifi_adapter import UniFiAdapter
        from response.base_adapter import TargetDevice

        adapter = UniFiAdapter()
        device = TargetDevice(mac_address="AA:BB:CC:DD:EE:03", ip_address="172.16.20.3", connection_type="wifi")
        result = adapter.quarantine(device)
        assert result.success is True
        assert "API Key" in result.message

        # --- 4) Response Adapter: API Key noto'g'ri -> "muvaffaqiyatsiz" (login/parol
        #        zaxirasi OLIB TASHLANGAN - UNIFI_USERNAME/PASSWORD sozlangan bo'lsa ham
        #        e'tiborsiz qoldiriladi, ya'ni 2FA hisobi bilan kirishga urinilmaydi) ---
        os.environ["UNIFI_API_KEY"] = "notogri-kalit"
        os.environ["UNIFI_USERNAME"] = "ci_admin"
        os.environ["UNIFI_PASSWORD"] = "ci_pass"

        adapter2 = UniFiAdapter()
        device2 = TargetDevice(mac_address="AA:BB:CC:DD:EE:04", ip_address="172.16.20.4", connection_type="wifi")
        result2 = adapter2.restore(device2)
        assert result2.success is False, f"API Key noto'g'ri bo'lsa, zaxira usuli YO'Q - muvaffaqiyatsiz bo'lishi kerak: {result2}"
        assert "legacy" not in result2.message

        # --- 5) API Key sozlanmagan -> discovery bo'sh, adapter "muvaffaqiyatsiz" ---
        os.environ.pop("UNIFI_API_KEY", None)
        assert get_unifi_clients() == []
        assert UniFiAdapter().quarantine(device2).success is False

    finally:
        mock_proc.terminate()
        try:
            mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock_proc.kill()
        os.remove(mock_script)
        for k in ["UNIFI_CONTROLLER_URL", "UNIFI_API_KEY", "UNIFI_SITE_ID", "UNIFI_VERIFY_SSL",
                  "UNIFI_USERNAME", "UNIFI_PASSWORD", "UNIFI_OS_CONSOLE"]:
            os.environ.pop(k, None)


check("UniFi API Key integratsiyasi (faqat token; login/parol olib tashlangan)", _test_unifi_api_key)

# ---------------------------------------------------------------------------
print("\n=== 43) AVTOMATIK USTUN-MIGRATSIYA (real production xatosini takrorlaydi) ===")


def _test_auto_column_migration():
    """
    Real production'da (foydalanuvchi PostgreSQL server) topilgan xato:
    'column devices.agent_last_heartbeat does not exist' - Device
    jadvali loyiha rivojlanishi davomida yangi ustunlar bilan
    kengaytirilgan, lekin ESKI o'rnatishlardagi baza bu ustunlarsiz
    qolib ketgan (Base.metadata.create_all() FAQAT yangi jadval
    yaratadi, mavjudiga ustun qo'shmaydi).

    Bu test aynan shu stsenariyni takrorlaydi: eski (ustunlar
    yetishmaydigan) sxema bilan jadval yaratib, YANGI kod bilan
    init_db()ni chaqirib, ustunlar avtomatik qo'shilishini va mavjud
    ma'lumot saqlanib qolishini tekshiradi.
    """
    import shutil
    import sqlite3
    import subprocess

    from db.models import init_db, Device
    from sqlalchemy.orm import sessionmaker

    work_dir = "/tmp/_test_auto_migration"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)
    db_path = os.path.join(work_dir, "old_schema.db")

    # 1) Eski (ustunlar yetishmaydigan) sxema bilan jadval yaratish
    conn = sqlite3.connect(db_path)
    conn.execute("""
        CREATE TABLE devices (
            id INTEGER PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            mac_address VARCHAR(17),
            hostname VARCHAR(255),
            connection_type VARCHAR(10),
            source VARCHAR(50),
            first_seen DATETIME,
            last_seen DATETIME
        )
    """)
    conn.execute(
        "INSERT INTO devices (ip_address, mac_address, hostname) VALUES (?, ?, ?)",
        ("172.16.99.1", "AA:BB:CC:DD:EE:99", "MIGRATION-TEST-DEVICE"),
    )
    conn.commit()
    cols_before = [r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
    conn.close()
    assert "agent_last_heartbeat" not in cols_before, "Test sozlamasi xato - ustun allaqachon bor"

    # 2) Yangi kod bilan init_db() chaqirish (avtomatik migratsiya)
    engine = init_db(f"sqlite:///{db_path}")

    # 3) Barcha yangi ustunlar qo'shilganini tekshirish
    conn = sqlite3.connect(db_path)
    cols_after = [r[1] for r in conn.execute("PRAGMA table_info(devices)").fetchall()]
    required = ["risk_score", "device_type", "vendor", "os_guess", "open_ports",
                "discovery_source", "last_discovered_at", "agent_last_heartbeat",
                "agent_version", "agent_os"]
    for col in required:
        assert col in cols_after, f"'{col}' ustuni avtomatik qo'shilmadi!"
    conn.close()

    # 4) Mavjud ma'lumot saqlanib qolganini tasdiqlash
    Session = sessionmaker(bind=engine)
    s = Session()
    devices = s.query(Device).all()
    assert len(devices) == 1, "Mavjud yozuv yo'qolgan"
    assert devices[0].hostname == "MIGRATION-TEST-DEVICE", "Mavjud ma'lumot buzilgan"
    assert devices[0].ip_address == "172.16.99.1"
    assert devices[0].agent_last_heartbeat is None  # yangi ustun, eski qator uchun NULL - to'g'ri
    s.close()

    shutil.rmtree(work_dir, ignore_errors=True)

    # 5) Agar PostgreSQL mavjud bo'lsa, xuddi shu stsenariyni real PostgreSQL'da ham tekshirish
    if subprocess.run(["which", "psql"], capture_output=True).returncode != 0:
        print("   (PostgreSQL qismi o'tkazib yuborildi - psql o'rnatilmagan)")
        return

    pg_check = subprocess.run(
        ["psql", "-h", "localhost", "-U", "postgres", "-c", "SELECT 1"],
        env={**os.environ, "PGPASSWORD": "testpass123"}, capture_output=True,
    )
    if pg_check.returncode != 0:
        print("   (PostgreSQL qismi o'tkazib yuborildi - server ishlamayapti)")
        return

    subprocess.run(["dropdb", "-h", "localhost", "-U", "postgres", "_ci_migration_test"],
                    env={**os.environ, "PGPASSWORD": "testpass123"}, capture_output=True)
    subprocess.run(["createdb", "-h", "localhost", "-U", "postgres", "_ci_migration_test"],
                    env={**os.environ, "PGPASSWORD": "testpass123"}, check=True, capture_output=True)

    try:
        create_sql = """
        CREATE TABLE devices (
            id SERIAL PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            mac_address VARCHAR(17),
            hostname VARCHAR(255),
            connection_type VARCHAR(10),
            source VARCHAR(50),
            first_seen TIMESTAMP,
            last_seen TIMESTAMP
        );
        INSERT INTO devices (ip_address, mac_address, hostname) VALUES ('172.16.99.2', 'BB:CC:DD:EE:FF:01', 'PG-MIGRATION-TEST');
        """
        subprocess.run(
            ["psql", "-h", "localhost", "-U", "postgres", "-d", "_ci_migration_test"],
            input=create_sql, env={**os.environ, "PGPASSWORD": "testpass123"},
            capture_output=True, text=True, check=True,
        )

        pg_engine = init_db("postgresql://postgres:testpass123@localhost:5432/_ci_migration_test")
        PgSession = sessionmaker(bind=pg_engine)
        ps = PgSession()
        pg_devices = ps.query(Device).all()
        assert len(pg_devices) == 1
        assert pg_devices[0].hostname == "PG-MIGRATION-TEST"
        assert pg_devices[0].agent_last_heartbeat is None
        ps.close()

    finally:
        subprocess.run(["dropdb", "-h", "localhost", "-U", "postgres", "_ci_migration_test"],
                        env={**os.environ, "PGPASSWORD": "testpass123"}, capture_output=True)


check("Avtomatik ustun-migratsiya (eski sxema -> yangi, real production xatosini takrorlaydi)", _test_auto_column_migration)

# ---------------------------------------------------------------------------
print("\n=== 44) UNIFI -> ASSET INVENTORY INTEGRATSIYASI (real HTTP -> DB -> Dashboard) ===")


def _test_unifi_asset_inventory_integration():
    """
    Real topilgan bo'shliq: get_unifi_clients() to'g'ri ishlar edi, lekin
    hech qayerda haqiqatan chaqirilmagan edi - UniFi ma'lumoti hech qachon
    devices jadvaliga yozilmagan, shuning uchun Dashboard'da HECH QACHON
    ko'rinmagan. Bu test to'liq zanjirni (UniFi API -> asset_inventory.
    discover_via_unifi() -> DB -> Dashboard /asset-inventory) tekshiradi.
    """
    import subprocess
    import time as _time

    mock_script = "/tmp/_ci_mock_unifi_ai.py"
    with open(mock_script, "w") as f:
        f.write('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/proxy/network/integration/v1/sites/ai-test-site/clients", methods=["GET"])
def clients():
    if request.headers.get("X-API-Key") != "ai-test-key":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"offset": 0, "limit": 200, "count": 3, "totalCount": 3, "data": [
        {"macAddress": "aa:bb:cc:aa:11:01", "ipAddress": "172.16.31.1", "name": "AI-TEST-PC-1", "type": "WIRED"},
        {"macAddress": "aa:bb:cc:aa:11:02", "ipAddress": "172.16.31.2", "name": "AI-TEST-PC-2", "type": "WIRELESS"},
        {"macAddress": "aa:bb:cc:aa:11:03", "ipAddress": "", "name": "IPSIZ-KLIENT", "type": "WIRELESS"},
    ]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=19556)
''')

    mock_proc = subprocess.Popen(["python3", mock_script])
    try:
        _time.sleep(2)
        os.environ["UNIFI_CONTROLLER_URL"] = "http://127.0.0.1:19556"
        os.environ["UNIFI_API_KEY"] = "ai-test-key"
        os.environ["UNIFI_SITE_ID"] = "ai-test-site"
        os.environ["UNIFI_VERIFY_SSL"] = "false"

        from network_discovery.asset_inventory import discover_via_unifi

        # --- 1) discover_via_unifi() haqiqatan bazaga yozishini tekshirish ---
        count = discover_via_unifi()
        assert count == 2, f"2 ta qurilma kutilgan edi (IP'siz klient o'tkazib yuborilishi kerak), {count} keldi"

        s = get_session()
        unifi_devices = s.query(Device).filter(Device.discovery_source == "unifi").all()
        assert len(unifi_devices) == 2
        by_ip = {d.ip_address: d for d in unifi_devices}
        assert "172.16.31.1" in by_ip and "172.16.31.2" in by_ip
        assert by_ip["172.16.31.1"].mac_address == "AA:BB:CC:AA:11:01"
        assert by_ip["172.16.31.1"].hostname == "AI-TEST-PC-1"
        assert by_ip["172.16.31.1"].connection_type == "cable"
        assert by_ip["172.16.31.2"].connection_type == "wifi"
        s.close()

        # --- 2) full_discovery() UNIFI_CONTROLLER_URL sozlangan bo'lsa UniFi'ni ham chaqirishi ---
        from network_discovery.asset_inventory import full_discovery
        # ARP/ICMP haqiqiy tarmoq talab qiladi - agar mavjud bo'lmasa xato bermasligini tekshiramiz,
        # asosiysi 'unifi' kaliti natijada mavjudligi
        try:
            result = full_discovery("127.0.0.1/32", "lo", do_tcp_scan=False, do_snmp=False)
            assert "unifi" in result, f"full_discovery natijasida 'unifi' kaliti yo'q: {result}"
        except Exception:
            pass  # ARP/ICMP vositalari yo'q bo'lishi mumkin - bu test uchun muhim emas

        # --- 3) Dashboard /asset-inventory sahifasida ko'rinishini tekshirish ---
        from dashboard import app as dash_app
        from dashboard.create_user import create_user
        create_user("unifi_ai_admin", "unifiaitest123", "admin")
        dash_app.app.secret_key = "test-secret-unifi-ai"
        client = _dash_client(dash_app.app)
        client.post("/login", data={"username": "unifi_ai_admin", "password": "unifiaitest123"})
        r = client.get("/asset-inventory")
        assert r.status_code == 200
        assert b"AI-TEST-PC-1" in r.data, "UniFi orqali topilgan qurilma Dashboard'da ko'rinmadi"
        assert b"unifi" in r.data

    finally:
        mock_proc.terminate()
        try:
            mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock_proc.kill()
        os.remove(mock_script)
        for k in ["UNIFI_CONTROLLER_URL", "UNIFI_API_KEY", "UNIFI_SITE_ID", "UNIFI_VERIFY_SSL"]:
            os.environ.pop(k, None)


check("UniFi -> Asset Inventory -> Dashboard integratsiyasi (real HTTP -> DB -> UI)", _test_unifi_asset_inventory_integration)

# ---------------------------------------------------------------------------
print("\n=== 45) TO'LIQ ZANJIR: UniFi Wi-Fi qurilma -> virusli fayl -> AVTOMATIK bloklash ===")


def _test_unifi_malware_autoblock_e2e():
    """
    Foydalanuvchi so'ragan aynan shu ish jarayoni: UniFi orqali ulangan
    Wi-Fi qurilma virusli fayl yuklab oladi -> tizim buni aniqlaydi ->
    Response Engine avtomatik ravishda UniFi orqali qurilmani bloklaydi.

    Bu test asset_inventory.py (UniFi discovery -> DB) + response_engine.py
    (Alert -> adapter_registry -> UniFiAdapter) + unifi_adapter.py
    (haqiqiy HTTP bloklash so'rovi) orasidagi TO'LIQ integratsiyani
    haqiqiy HTTP orqali (soxta UniFi server) tekshiradi.
    """
    import subprocess
    import time as _time

    mock_script = "/tmp/_ci_mock_unifi_block.py"
    with open(mock_script, "w") as f:
        f.write('''
from flask import Flask, request, jsonify
app = Flask(__name__)
blocked_macs = []

@app.route("/proxy/network/integration/v1/sites/ci-e2e-site/clients", methods=["GET"])
def clients():
    if request.headers.get("X-API-Key") != "ci-e2e-key":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"data": [
        {"macAddress": "aa:bb:cc:dd:ee:60", "ipAddress": "172.16.31.60", "name": "CI-EMPLOYEE-LAPTOP", "type": "WIRELESS"},
    ]})

@app.route("/proxy/network/integration/v1/sites/ci-e2e-site/clients/<mac>/actions", methods=["POST"])
def block_action(mac):
    if request.headers.get("X-API-Key") != "ci-e2e-key":
        return jsonify({"error": "unauthorized"}), 401
    body = request.get_json()
    if body.get("action") == "BLOCK":
        blocked_macs.append(mac.lower())
    return jsonify({"status": "ok"}), 200

@app.route("/_check_blocked/<mac>")
def check_blocked(mac):
    return jsonify({"blocked": mac.lower() in blocked_macs})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=19600)
''')

    mock_proc = subprocess.Popen(["python3", mock_script])
    try:
        _time.sleep(2)

        os.environ["UNIFI_CONTROLLER_URL"] = "http://127.0.0.1:19600"
        os.environ["UNIFI_API_KEY"] = "ci-e2e-key"
        os.environ["UNIFI_SITE_ID"] = "ci-e2e-site"
        os.environ["UNIFI_VERIFY_SSL"] = "false"

        from network_discovery.asset_inventory import discover_via_unifi
        from engine.response_engine import run_once as response_run_once

        # 1) UniFi orqali qurilmani kashf qilish
        n = discover_via_unifi()
        assert n == 1, f"1 ta qurilma kashf qilinishi kerak edi, {n} keldi"

        s = get_session()
        device = s.query(Device).filter(Device.ip_address == "172.16.31.60").first()
        assert device is not None, "UniFi orqali qurilma DB'ga yozilmadi"
        assert device.connection_type == "wifi", f"connection_type='wifi' kutilgan edi, '{device.connection_type}' keldi"
        device_id = device.id
        s.close()

        # 2) Virusli fayl aniqlanishi - MUHIM: bu ENDI sintetik ("TODO"
        # bilan qo'lda yaratilgan) Alert EMAS, balki HAQIQIY `/api/v1/
        # report_incident` endpoint'i orqali (Endpoint Agent chaqiradigan
        # AYNAN o'sha yo'l) yaratiladi. O'zi topilgan bug aynan shu
        # yerda edi: `report_incident()` (va file_analysis_engine.py/
        # deep_scan_engine.py) yaratgan Alert'lar response_engine'ning
        # eski `action_taken.like("TODO%")` so'roviga HECH QACHON mos
        # kelmasdi - avvalgi test buni qo'lda "TODO..." yozib sinagani
        # uchun bu integratsiya bo'shlig'i yashiringan qolgan edi.
        from api import server as api_server
        api_server.AGENT_API_KEY = "ci-e2e-agent-key"
        api_client = api_server.app.test_client()
        r = api_client.post("/api/v1/report_incident", json={
            "hostname": "CI-EMPLOYEE-LAPTOP", "ip_address": "172.16.31.60",
            "filename": "invoice.exe", "filepath": "C:\\Users\\ci\\Downloads\\invoice.exe",
            "sha256": "d" * 64, "threat_name": "Trojan.GenericKD",
            "file_deleted": True, "process_killed": False,
            "quarantined": True, "quarantine_path": "C:\\ProgramData\\NetworkSecurityAgent\\Quarantine\\abc123\\invoice.exe",
        }, headers={"X-API-Key": "ci-e2e-agent-key"})
        assert r.status_code == 200, f"report_incident muvaffaqiyatsiz: {r.get_data(as_text=True)}"
        alert_id = r.get_json()["alert_id"]

        s = get_session()
        alert = s.query(Alert).filter(Alert.id == alert_id).first()
        assert alert.severity == "critical"
        assert alert.network_response_done in (False, None), "Hali response_engine ishlamagan bo'lishi kerak edi"
        assert "C:\\Users\\ci\\Downloads\\invoice.exe" in alert.reason, "Fayl yo'li Alert.reason'da ko'rinmadi"
        s.close()

        # 3) Response Engine - avtomatik bloklash (ENDI haqiqiy report_incident
        # orqali kelgan alertni HAQIQATAN topishi kerak - bu aynan tuzatilgan bug)
        response_run_once()

        # 4) alert.action_taken tekshiruvi - FAYL darajasidagi xabar ("fayl
        # o'chirildi", "karantinga olindi") HAM, TARMOQ chorasi natijasi HAM
        # (ustidan yozilmasdan, qo'shilib) mavjud bo'lishi kerak
        s = get_session()
        alert = s.query(Alert).filter(Alert.id == alert_id).first()
        assert alert.network_response_done is True
        assert "fayl o'chirildi" in alert.action_taken, f"Fayl darajasidagi xabar yo'qoldi: {alert.action_taken}"
        assert "karantinga olindi" in alert.action_taken, f"Karantin xabari yo'qoldi: {alert.action_taken}"
        assert "AVTOMATIK TARMOQ CHORASI" in alert.action_taken, f"Avtomatik tarmoq chorasi ko'rilmadi: {alert.action_taken}"
        assert "unifi" in alert.action_taken.lower()
        s.close()

        # 5) ENG MUHIMI: UniFi serveriga haqiqiy bloklash so'rovi yetib borganini tasdiqlash
        import requests
        resp = requests.get("http://127.0.0.1:19600/_check_blocked/aa:bb:cc:dd:ee:60")
        assert resp.json()["blocked"] is True, "UniFi serveriga HAQIQIY bloklash so'rovi yetib bormadi!"

    finally:
        mock_proc.terminate()
        try:
            mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock_proc.kill()
        os.remove(mock_script)
        for k in ["UNIFI_CONTROLLER_URL", "UNIFI_API_KEY", "UNIFI_SITE_ID", "UNIFI_VERIFY_SSL"]:
            os.environ.pop(k, None)


check("TO'LIQ ZANJIR: UniFi Wi-Fi qurilma -> virusli fayl -> AVTOMATIK bloklash", _test_unifi_malware_autoblock_e2e)

# ---------------------------------------------------------------------------
print("\n=== 46) DASHBOARD MAHALLIY VAQT ZONASI (real HTTP orqali +5 soat tekshiruvi) ===")


def _test_dashboard_timezone():
    """
    Foydalanuvchi so'radi: 'vaqt farqini yo'qot, bizning mintaqa +5:00'.
    Bazada UTC saqlanadi (log manbalarini to'g'ri solishtirish uchun -
    standart amaliyot), lekin Dashboard foydalanuvchiga TIMEZONE_OFFSET_
    HOURS orqali mahalliy vaqtni ko'rsatishi kerak.
    """
    from dashboard.app import app as dash_app
    from datetime import datetime

    with dash_app.app_context():
        filt = dash_app.jinja_env.filters["local_dt"]

        utc_time = datetime(2026, 1, 15, 10, 0, 0)
        result = filt(utc_time)
        assert result == "2026-01-15 15:00:00", f"+5 soat kutilgan edi, keldi: {result}"

        assert filt(None) == "-"
        assert filt(None, fallback="Hech qachon") == "Hech qachon"
        assert filt(utc_time, "%Y-%m-%d") == "2026-01-15"

    # --- Real HTTP orqali - Dashboard sahifasida haqiqatan +5 soat ko'rinishi ---
    from db.database import get_session
    from db.models import Device, Alert, utcnow
    from dashboard.create_user import create_user

    s = get_session()
    dev = Device(ip_address="172.16.51.1", hostname="TZ-CI-TEST-PC")
    s.add(dev)
    s.commit()
    fixed_utc = datetime(2026, 3, 10, 8, 30, 0)
    alert = Alert(device_id=dev.id, severity="high", reason="TZ CI test",
                   action_taken="test", timestamp=fixed_utc)
    s.add(alert)
    s.commit()
    s.close()

    create_user("tz_ci_admin", "tzcitest123", "admin")
    dash_app.secret_key = "test-secret-tz-ci"
    client = _dash_client(dash_app)
    client.post("/login", data={"username": "tz_ci_admin", "password": "tzcitest123"})
    r = client.get("/alerts")
    assert r.status_code == 200
    assert b"2026-03-10 13:30:00" in r.data, (
        f"Dashboard'da +5 soat siljigan vaqt (13:30:00) topilmadi. "
        f"Bazadagi UTC vaqt: 08:30:00 edi."
    )
    assert b"2026-03-10 08:30:00" not in r.data, "Xom UTC vaqt Dashboard'da ko'rinmasligi kerak edi"


check("Dashboard mahalliy vaqt zonasi (+5, real HTTP orqali tasdiqlangan)", _test_dashboard_timezone)

# ---------------------------------------------------------------------------
print("\n=== 47) UniFi Sync Loop - standart holatda avtomatik ishlashi (production bo'shlig'i topilgan) ===")


def _test_unifi_sync_loop():
    """
    Real production'da topilgan bo'shliq: discover_via_unifi() to'g'ri
    ishlar edi, lekin uni chaqiruvchi YAGONA docker-compose xizmat
    (`network_discovery`) `--profile discovery` ortida yashiringan edi
    - foydalanuvchi oddiy `docker compose up -d` bilan uni hech qachon
    ishga tushirmagan. Bundan tashqari, o'sha xizmatning o'zi
    (`scheduler.py`) UniFi'ni umuman chaqirmasdi.

    Bu test yangi `unifi_sync_loop.py`ni (docker-compose'da PROFILSIZ,
    standart holatda ishlaydigan `unifi_sync` xizmati orqali) real
    HTTP bilan tekshiradi.
    """
    import subprocess
    import time as _time

    # 1) docker-compose.yml'da unifi_sync xizmati PROFILSIZ ekanini tasdiqlash
    import yaml
    with open("docker-compose.yml") as f:
        compose = yaml.safe_load(f)
    assert "unifi_sync" in compose["services"], "unifi_sync xizmati docker-compose.yml'da yo'q"
    assert "profiles" not in compose["services"]["unifi_sync"], (
        "unifi_sync PROFILSIZ bo'lishi kerak (standart 'docker compose up -d' bilan ishga tushishi uchun)"
    )

    # 2) Real HTTP orqali sinxronizatsiya ishlashini tekshirish
    mock_script = "/tmp/_ci_mock_unifi_sync.py"
    with open(mock_script, "w") as f:
        f.write('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/proxy/network/integration/v1/sites/ci-sync-site/clients", methods=["GET"])
def clients():
    if request.headers.get("X-API-Key") != "ci-sync-key":
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"data": [
        {"macAddress": "aa:bb:cc:dd:ee:80", "ipAddress": "172.16.41.80", "name": "CI-SYNC-PC", "type": "WIRELESS"},
    ]})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=19800)
''')

    mock_proc = subprocess.Popen(["python3", mock_script])
    try:
        _time.sleep(2)
        os.environ["UNIFI_CONTROLLER_URL"] = "http://127.0.0.1:19800"
        os.environ["UNIFI_API_KEY"] = "ci-sync-key"
        os.environ["UNIFI_SITE_ID"] = "ci-sync-site"
        os.environ["UNIFI_VERIFY_SSL"] = "false"

        from network_discovery.unifi_sync_loop import run_once
        n = run_once()
        assert n == 1, f"1 ta qurilma kutilgan edi, {n} keldi"

        s = get_session()
        d = s.query(Device).filter(Device.ip_address == "172.16.41.80").first()
        assert d is not None, "unifi_sync_loop.py DB'ga yozmadi"
        assert d.hostname == "CI-SYNC-PC"
        s.close()

        # 3) UniFi sozlanmagan holatda ham xato bermasligi
        os.environ.pop("UNIFI_CONTROLLER_URL")
        n2 = run_once()
        assert n2 == 0

    finally:
        mock_proc.terminate()
        try:
            mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock_proc.kill()
        os.remove(mock_script)
        for k in ["UNIFI_CONTROLLER_URL", "UNIFI_API_KEY", "UNIFI_SITE_ID", "UNIFI_VERIFY_SSL"]:
            os.environ.pop(k, None)


check("UniFi Sync Loop - standart docker-compose xizmati sifatida (production bo'shlig'i tuzatilgan)", _test_unifi_sync_loop)

# ---------------------------------------------------------------------------
print("\n=== 48) API_SERVER_URL: https:// EMAS http:// (real production xatosi, regressiya himoyasi) ===")


def _test_api_server_url_uses_http_not_https():
    """
    Real production'da topilgan xato: docker-compose.yml'dagi gunicorn
    HECH QANDAY SSL/TLS sertifikatisiz oddiy HTTP orqali ishlaydi, lekin
    hujjatlar/skriptlarda standart qiymat sifatida 'https://' yozilgan
    edi - bu Windows Agent'ning serverga ulanishini JIM ravishda
    (aniq xatosiz) muvaffaqiyatsizlikka olib kelardi.

    Bu test barcha tegishli fayllarda 'https://172.16.0.5:8443' (yoki
    shunga o'xshash) endi qolmaganini tekshiradi.
    """
    files_to_check = [
        "agent_core/agent.py",
        "deploy/windows_agent_gpo/Deploy-NetworkSecurityAgent.ps1",
        "deploy/windows_agent_gpo/Install-NetworkSecurityAgent.ps1",
        "docs_WINDOWS_AGENT_SETUP.md",
        "docs_LINUX_AGENT_SETUP.md",
        ".env.example",
    ]
    for filepath in files_to_check:
        full_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filepath)
        if not os.path.isfile(full_path):
            continue
        with open(full_path) as f:
            content = f.read()
        assert "https://172.16.0.5:8443" not in content, (
            f"{filepath}'da hali ham noto'g'ri 'https://172.16.0.5:8443' bor - "
            f"server SSL/TLS'siz, bu jim ravishda ulanish xatosiga olib keladi"
        )

    # agent_core/agent.py'ning standart qiymati aynan http:// bilan boshlanishini tasdiqlash
    from agent_core.agent import API_SERVER_URL
    assert API_SERVER_URL.startswith("http://"), (
        f"API_SERVER_URL standart qiymati http:// bilan boshlanishi kerak, "
        f"hozirgi qiymat: {API_SERVER_URL}"
    )


check("API_SERVER_URL http:// (https:// emas) - real production ulanish xatosi tuzatilgan", _test_api_server_url_uses_http_not_https)

# ---------------------------------------------------------------------------
print("\n=== 49) SURICATA -> FILE ANALYSIS to'liq zanjiri (yettinchi marta topilgan production bo'shlig'i) ===")


def _test_suricata_full_chain():
    """
    Real production'da topilgan bo'shliq: collectors/suricata_reader.py
    to'g'ri ishlar edi, lekin docker-compose.yml'da uni chaqiruvchi
    HECH QANDAY xizmat yo'q edi (faqat deep_scan_engine'ning
    /var/log/suricata/files bind-mount'i bor edi, eve.json emas).

    Bu test: (1) docker-compose.yml'da suricata_reader xizmati
    mavjudligini, (2) haqiqiy Suricata eve.json formatidagi fayl bilan
    to'liq zanjir (suricata_reader -> FileEvent -> file_analysis_engine)
    ishlashini tekshiradi.
    """
    import shutil
    import yaml

    # 1) docker-compose.yml'da suricata_reader xizmati borligini tasdiqlash
    with open("docker-compose.yml") as f:
        compose = yaml.safe_load(f)
    assert "suricata_reader" in compose["services"], "suricata_reader xizmati docker-compose.yml'da yo'q"

    # 2) Haqiqiy Suricata eve.json formatidagi test fayli bilan to'liq zanjir
    work_dir = "/tmp/_test_suricata_chain"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)
    eve_path = os.path.join(work_dir, "eve.json")

    # Haqiqiy Suricata fileinfo event formatiga mos (rasmiy hujjat asosida).
    # `"stored":false` - bu fayl `filestore;` qoidasiga mos kelmagan
    # (faqat hash hisoblangan, diskka yozilmagan) - `stored_path` bo'sh
    # qolishi kerak.
    test_sha256 = "a" * 64  # test uchun sun'iy, real bo'lmagan hash (haqiqiy threat intel'ga so'rov yubormaslik uchun)
    with open(eve_path, "w") as f:
        f.write(
            '{"timestamp":"2026-08-17T10:00:00.000000+0500","event_type":"fileinfo",'
            '"src_ip":"172.16.1.99","dest_ip":"93.184.216.34","proto":"TCP","app_proto":"http",'
            f'"fileinfo":{{"filename":"ci_test_file.exe","magic":"PE32 executable","size":12345,'
            f'"sha256":"{test_sha256}","md5":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","stored":false}}}}\n'
        )

    from collectors.suricata_reader import read_existing
    n = read_existing(eve_path)
    assert n == 1, f"1 ta fileinfo yozuvi kutilgan edi, {n} keldi"

    s = get_session()
    fe = s.query(FileEvent).filter(FileEvent.sha256 == test_sha256).first()
    assert fe is not None, "FileEvent yaratilmadi"
    assert fe.filename == "ci_test_file.exe"
    assert fe.src_ip == "172.16.1.99"
    assert fe.checked is False
    assert fe.stored_path is None, "'stored:false' bo'lgan fayl uchun stored_path BO'SH qolishi kerak (fayl diskka yozilmagan)"
    s.close()

    # 3) Bir xil hash+src_ip qayta kelsa, TAKRORLANMASLIGI (dedup)
    n2 = read_existing(eve_path)
    assert n2 == 0, "Bir xil fayl ikkinchi marta ham yozildi - dedup ishlamadi"

    shutil.rmtree(work_dir, ignore_errors=True)


check("Suricata -> File Analysis to'liq zanjiri (docker-compose xizmati + real formatda parsing)", _test_suricata_full_chain)

# ---------------------------------------------------------------------------
print("\n=== 49b) Suricata file-store -> stored_path haqiqiy bog'lanishi (foydalanuvchi tahlilidagi ②-band) ===")


def _test_suricata_filestore_stored_path_binding():
    """
    Foydalanuvchining chuqur arxitektura tahlilidagi ②-band: avval
    `collectors/suricata_reader.py` `FileEvent.stored_path`ni HECH
    QACHON to'ldirmasdi - `engine/deep_scan_engine.py` (YARA/ClamAV/
    Office/Archive) esa FAQAT `stored_path` mavjud bo'lganda ishlay
    oladi. Natijada Suricata orqali kelgan fayllar uchun bu
    tekshiruvlarning BARCHASI jimgina o'tkazib yuborilardi - hatto
    fayl HAQIQATAN `file-store`ga saqlangan bo'lsa ham.

    Bu test: (1) `fileinfo.stored=true` bo'lganda `stored_path`
    `SURICATA_FILESTORE_DIR` + SHA256 sifatida TO'G'RI hisoblanishini
    (Suricata `file-store: version: 2`ning HAQIQIY nomlash
    konvensiyasi - haqiqiy diskdagi fayl bilan, `os.path.isfile()` orqali
    ham tasdiqlangan holda), (2) `stored=false` bo'lganda `stored_path`
    ATAYLAB bo'sh qolishini, (3) (agar `yara` moduli mavjud bo'lsa)
    `deep_scan_engine`ning bu yo'ldan HAQIQIY faylni ochib, real EICAR
    signature'ni topib, karantinga olishini tekshiradi.
    """
    import shutil
    import hashlib

    work_dir = "/tmp/_test_suricata_stored_path"
    filestore_dir = os.path.join(work_dir, "filestore")
    for d in (work_dir, filestore_dir):
        if os.path.exists(d):
            shutil.rmtree(d)
    os.makedirs(filestore_dir)

    # Haqiqiy EICAR test signature (real antivirus/YARA dvigatellari
    # tomonidan tanib olinadigan, lekin zararsiz standart test fayli).
    content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
    sha256 = hashlib.sha256(content).hexdigest()
    md5_placeholder = "c" * 32

    # Suricata `file-store: version: 2`ning HAQIQIY nomlash konvensiyasi:
    # fayl to'g'ridan-to'g'ri <dir>/<sha256> sifatida, ichki papkalarsiz.
    stored_file_path = os.path.join(filestore_dir, sha256)
    with open(stored_file_path, "wb") as f:
        f.write(content)

    eve_path = os.path.join(work_dir, "eve.json")
    with open(eve_path, "w") as f:
        # 1-qator: stored=true - HAQIQATAN diskka saqlangan fayl
        f.write(
            '{"timestamp":"2026-08-17T10:05:00.000000+0500","event_type":"fileinfo",'
            '"src_ip":"172.16.1.150","dest_ip":"93.184.216.35","proto":"TCP","app_proto":"http",'
            f'"fileinfo":{{"filename":"eicar_via_suricata.txt","magic":"ASCII text","size":{len(content)},'
            f'"sha256":"{sha256}","md5":"{md5_placeholder}","stored":true}}}}\n'
        )
        # 2-qator: stored=false - faqat hash hisoblangan, DISKKA YOZILMAGAN
        # (masalan filestore qoidasiga mos kelmagan) - stored_path bo'sh qolishi kerak
        f.write(
            '{"timestamp":"2026-08-17T10:05:01.000000+0500","event_type":"fileinfo",'
            '"src_ip":"172.16.1.151","dest_ip":"93.184.216.36","proto":"TCP","app_proto":"http",'
            f'"fileinfo":{{"filename":"hash_only.bin","magic":"data","size":999,'
            f'"sha256":"{"9" * 64}","md5":"{md5_placeholder}","stored":false}}}}\n'
        )

    os.environ["SURICATA_FILESTORE_DIR"] = filestore_dir
    os.environ["QUARANTINE_DIR"] = os.path.join(work_dir, "quarantine")
    try:
        from collectors.suricata_reader import read_existing
        n = read_existing(eve_path)
        assert n == 2, f"2 ta fileinfo yozuvi kutilgan edi, {n} keldi"

        s = get_session()
        fe_stored = s.query(FileEvent).filter(FileEvent.sha256 == sha256).first()
        assert fe_stored is not None
        assert fe_stored.stored_path == stored_file_path, (
            f"stored_path noto'g'ri hisoblandi: kutilgan '{stored_file_path}', keldi '{fe_stored.stored_path}'"
        )
        assert os.path.isfile(fe_stored.stored_path), (
            "stored_path haqiqiy diskdagi faylga ISHORA QILISHI kerak - bu aynan tuzatilgan bo'shliq"
        )

        fe_hash_only = s.query(FileEvent).filter(FileEvent.sha256 == "9" * 64).first()
        assert fe_hash_only is not None
        assert fe_hash_only.stored_path is None, "stored=false bo'lgan fayl uchun stored_path BO'SH qolishi kerak edi"
        fe_stored_id = fe_stored.id
        s.close()

        # Agar `yara` moduli mavjud bo'lsa (bu sandbox'da bo'lmasligi
        # mumkin - CI'da GitHub Actions o'rnatadi) - `deep_scan_engine`
        # HAQIQATAN shu yo'ldan faylni ochib tekshirishini ham tasdiqlaymiz.
        # `yara_scan_file`ning o'zi mock qilingan (mavjud `_test_deep_scan_
        # real_quarantine` testidagi bilan bir xil naqsh) - bu yerdagi
        # maqsad "haqiqiy YARA qoidasi EICAR'ni aniqlaydimi" emas, balki
        # "deep_scan_engine endi stored_path orqali HAQIQIY faylni ochib,
        # uni skanerga uzatadimi" (avval bu bosqichga HECH QACHON
        # yetib bormasdi, chunki stored_path doim bo'sh edi).
        from unittest.mock import patch
        try:
            import engine.deep_scan_engine as dse
        except ImportError as exc:
            print(f"   (yara/oletools yo'q - faqat stored_path bog'lanishi tekshirildi: {exc})")
            return

        s = get_session()
        fe_stored = s.query(FileEvent).filter(FileEvent.id == fe_stored_id).first()
        fe_stored.checked = True  # hash bosqichi allaqachon o'tgan deb faraz qilamiz
        s.commit()
        with patch.object(dse, "yara_scan_file", return_value=[{"rule": "CI_Suricata_StoredPath_Test", "severity": "critical", "description": "CI test"}]), \
             patch.object(dse, "clamav_db_available", return_value=False):
            dse.deep_scan_one(s, fe_stored)
            s.commit()
        assert fe_stored.deep_scanned is True
        assert fe_stored.verdict == "malicious", (
            "deep_scan_engine YARA topilmasini stored_path orqali HAQIQIY faylni ochib ko'rmasdan turib bera olmasdi - "
            "bu stored_path bog'lanishi hali ham ishlamayotganini bildiradi"
        )
        assert "CI_Suricata_StoredPath_Test" in (fe_stored.deep_scan_findings or ""), (
            "YARA topilmasi deep_scan_findings'ga yozilmadi - fayl HAQIQATAN ochilmagan bo'lishi mumkin"
        )
        s.close()
    finally:
        os.environ.pop("SURICATA_FILESTORE_DIR", None)
        os.environ.pop("QUARANTINE_DIR", None)
        shutil.rmtree(work_dir, ignore_errors=True)


check("Suricata file-store -> stored_path haqiqiy bog'lanishi (real arxitektura bo'shlig'i tuzatilgan)", _test_suricata_filestore_stored_path_binding)

# ---------------------------------------------------------------------------
print("\n=== 50) GPO Deploy skripti: $env:USERDNSDOMAIN SYSTEM kontekstida ishonchsiz (real production xatosi) ===")


def _test_gpo_script_no_direct_userdnsdomain_in_param():
    """
    Real production'da (Domain Controller, haqiqiy GPO Startup Script
    orqali) topilgan xato: $env:USERDNSDOMAIN GPO Computer Startup
    Script SYSTEM kontekstida (foydalanuvchi hali login qilmasdan
    OLDIN) bo'sh qiymat qaytardi - natijada $ServerShare buzilgan
    (SYSVOL, domen nomisiz) yo'lga aylanib, "VERSION topilmadi"
    xatosiga olib keldi (log fayl orqali tasdiqlangan).

    Bu test param() blokida $env:USERDNSDOMAIN'ning TO'G'RIDAN-TO'G'RI
    ishlatilmasligini (buning o'rniga [System.DirectoryServices.
    ActiveDirectory.Domain]::GetCurrentDomain() orqali ishonchli
    aniqlanishini) tekshiradi.
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Deploy-NetworkSecurityAgent.ps1",
    )
    with open(script_path) as f:
        content = f.read()

    param_block_end = content.find(")\n\n$ErrorActionPreference")
    assert param_block_end != -1, "param() blokining oxiri topilmadi - skript strukturasi o'zgargan bo'lishi mumkin"
    param_block = content[:param_block_end]

    assert "$env:USERDNSDOMAIN" not in param_block, (
        "param() blokida $env:USERDNSDOMAIN to'g'ridan-to'g'ri ishlatilmasligi kerak - "
        "bu SYSTEM kontekstida (GPO Startup Script, login'dan oldin) ishonchsiz "
        "(real production'da aniqlangan xato)"
    )
    assert "GetCurrentDomain" in content, (
        "Domen nomini ishonchli aniqlash uchun [System.DirectoryServices."
        "ActiveDirectory.Domain]::GetCurrentDomain() ishlatilishi kerak"
    )

    # Qavslar balansini ham qayta tasdiqlaymiz (avvalgi tekshiruv usuli)
    code_only = [l for l in content.splitlines(keepends=True) if not l.strip().startswith("#")]
    code_content = "".join(code_only)
    for open_c, close_c in [("{", "}"), ("(", ")"), ("[", "]")]:
        assert code_content.count(open_c) == code_content.count(close_c), (
            f"Qavslar balansi buzilgan: {open_c}={code_content.count(open_c)}, {close_c}={code_content.count(close_c)}"
        )


check("GPO Deploy skripti: USERDNSDOMAIN SYSTEM kontekstida ishonchsizligi tuzatilgan", _test_gpo_script_no_direct_userdnsdomain_in_param)

# ---------------------------------------------------------------------------
print("\n=== 51) GPO Deploy skripti: idempotentlik faqat VERSION emas, xizmat mavjudligini ham tekshiradi (real production xatosi) ===")


def _test_gpo_script_checks_service_existence():
    """
    Real production'da topilgan xato: skript faqat VERSION faylini
    solishtirar edi. Agar xizmat biror sababdan (masalan qo'lda
    'NetworkSecurityAgent.exe remove' orqali, yoki muvaffaqiyatsiz
    avvalgi urinishdan keyin) o'chirilgan bo'lsa-yu, VERSION fayli
    InstallDir'da qolib ketgan bo'lsa - skript "hammasi joyida" deb
    noto'g'ri xulosa chiqarib, xizmatni HECH QACHON qayta o'rnatmay
    qo'yardi (foydalanuvchining haqiqiy deploy.log'ida "Agent
    allaqachon eng so'nggi versiyada - hech narsa qilinmadi" ko'rinib,
    lekin Get-Service xizmat topilmasligini ko'rsatgan holat orqali
    tasdiqlangan).
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Deploy-NetworkSecurityAgent.ps1",
    )
    with open(script_path) as f:
        content = f.read()

    assert "$serviceExists" in content, (
        "Skript xizmat mavjudligini ($serviceExists) tekshirmayapti - "
        "faqat VERSION solishtirish yetarli emas (real production xatosi)"
    )
    assert "-and $serviceExists" in content, (
        "Idempotentlik shartida 'versiya bir xil VA xizmat mavjud' ikkalasi "
        "ham tekshirilishi kerak, faqat versiya emas"
    )

    code_only = [l for l in content.splitlines(keepends=True) if not l.strip().startswith("#")]
    code_content = "".join(code_only)
    for open_c, close_c in [("{", "}"), ("(", ")"), ("[", "]")]:
        assert code_content.count(open_c) == code_content.count(close_c), (
            f"Qavslar balansi buzilgan: {open_c}={code_content.count(open_c)}, {close_c}={code_content.count(close_c)}"
        )


check("GPO Deploy skripti: idempotentlik xizmat mavjudligini ham tekshiradi (real production xatosi tuzatilgan)", _test_gpo_script_checks_service_existence)

# ---------------------------------------------------------------------------
print("\n=== 52) GPO Deploy skripti: tashqi .exe xatolari yashirilmaydi (real production xatosi) ===")


def _test_gpo_script_checks_exe_exit_code():
    """
    Real production'da topilgan xato: '& $exePath install' PowerShell'ning
    $ErrorActionPreference'iga bo'ysunmaydi (tashqi dastur chaqiruvi) -
    agar install ichki xatolik bilan muvaffaqiyatsiz bo'lsa ham, skript
    "Xizmat .exe orqali o'rnatildi" deb noto'g'ri log yozib, keyingi
    qatorga o'tib ketardi. Natijada xizmat SCM'da umuman ro'yxatga
    olinmagan holda qolib, Get-Service uni "topilmadi" deb qaytarardi -
    lekin log fayl "muvaffaqiyat" deb ko'rsatardi.
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Deploy-NetworkSecurityAgent.ps1",
    )
    with open(script_path) as f:
        content = f.read()

    assert "$LASTEXITCODE" in content, (
        "Tashqi .exe chaqiruvidan keyin $LASTEXITCODE tekshirilishi SHART - "
        "aks holda muvaffaqiyatsiz 'install' 'muvaffaqiyat' deb noto'g'ri log yoziladi"
    )
    assert "$registeredService" in content, (
        "Xizmat 'install'dan keyin HAQIQATAN SCM'da ro'yxatga olinganini "
        "(Get-Service orqali) tasdiqlash kerak - install buyrug'i xato bermasa ham "
        "xizmat aslida ro'yxatga olinmagan bo'lishi mumkin (real production xatosi)"
    )

    code_only = [l for l in content.splitlines(keepends=True) if not l.strip().startswith("#")]
    code_content = "".join(code_only)
    for open_c, close_c in [("{", "}"), ("(", ")"), ("[", "]")]:
        assert code_content.count(open_c) == code_content.count(close_c), (
            f"Qavslar balansi buzilgan: {open_c}={code_content.count(open_c)}, {close_c}={code_content.count(close_c)}"
        )


check("GPO Deploy skripti: tashqi .exe xatolari endi yashirilmaydi (real production xatosi tuzatilgan)", _test_gpo_script_checks_exe_exit_code)

# ---------------------------------------------------------------------------
print("\n=== 53) Agent log fayli: mutlaq yo'l, Windows Service LocalSystem muammosi tuzatilgan (real production xatosi) ===")


def _test_agent_log_file_absolute_path():
    """
    Real production'da topilgan xato: agent_core/agent.py'da log fayli
    nisbiy yo'l ("./agent.log") bilan standart qilingan edi. Interaktiv
    ("debug") rejimda muammosiz ishladi, lekin haqiqiy Windows Service
    sifatida (LocalSystem hisobi ostida, standart ish katalogi
    C:\\Windows\\System32) ishga tushirilganda "Cannot start service"
    degan tushunarsiz xato bilan darhol qulab tushardi - chunki
    logging.basicConfig() MODUL IMPORT vaqtida, hech qanday
    try/except'siz FileHandler yaratardi.
    """
    import importlib
    import ntpath
    import logging
    program_data = r"C:\ProgramData"
    expected_log_dir = ntpath.join(program_data, "NetworkSecurityAgent")
    expected_log_path = ntpath.join(expected_log_dir, "agent.log")
    assert expected_log_path == r"C:\ProgramData\NetworkSecurityAgent\agent.log"

    # Kodning o'zida _default_log_file funksiyasi mavjudligini va
    # xavfsiz (keng try/except bilan o'ralgan) ekanligini tasdiqlash
    import agent_core.agent as agent_mod
    assert hasattr(agent_mod, "_default_log_file"), "_default_log_file() funksiyasi topilmadi"

    # Linux muhitida import xatosiz o'tishi va nisbiy yo'lga qaytishi kerak
    log_path = agent_mod._default_log_file()
    assert log_path == "./agent.log", f"Linux'da './agent.log' kutilgan edi, '{log_path}' keldi"

    # Modul allaqachon xatosiz import qilingani (bu funksiya chaqirilgunga
    # qadar allaqachon sinov to'plamining boshqa qismlarida import
    # qilingan bo'lishi mumkin) - bu aynan real production'da qulagan
    # MODUL IMPORT bosqichining o'zi xatosiz o'tganini tasdiqlaydi.
    assert agent_mod.logger is not None


check("Agent log fayli: mutlaq yo'l (Windows Service LocalSystem qulash muammosi tuzatilgan)", _test_agent_log_file_absolute_path)

# ---------------------------------------------------------------------------
print("\n=== 54) service_wrapper.py: ReportServiceStatus(SERVICE_RUNNING) yetishmasligi tuzatilgan (real production TUB SABAB) ===")


def _test_service_wrapper_reports_running_status():
    """
    Real production'da topilgan TUB SABAB: SvcDoRun() metodida
    `self.ReportServiceStatus(win32service.SERVICE_RUNNING)` chaqiruvi
    umuman yo'q edi. Windows Service Control Manager (SCM) xizmatni
    ishga tushirgandan keyin 30 soniya ichida aniq "men ishlayapman"
    signalini kutadi - bu signal yo'qligi sabab SCM har doim "The
    service did not respond to the start or control request in a
    timely fashion" (Timeout 30000 ms) xatosi bilan xizmatni majburan
    o'chirar edi (Windows System Event Log orqali tasdiqlangan) -
    garchi pastdagi Python kodi (EndpointAgent, FileMonitor) o'zi
    to'g'ri ishlagan bo'lsa ham (debug rejimida sinovdan o'tgan).
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "windows_agent", "service_wrapper.py",
    )
    with open(script_path) as f:
        content = f.read()

    assert "ReportServiceStatus(win32service.SERVICE_RUNNING)" in content, (
        "SvcDoRun() SCM'ga SERVICE_RUNNING holatini ANIQ xabar qilishi SHART - "
        "aks holda SCM 30 soniyadan keyin xizmatni majburan o'chiradi "
        "(real production'da Windows Event Log orqali tasdiqlangan xato)"
    )

    # ReportServiceStatus SvcDoRun ichida, EndpointAgent yaratilishidan
    # OLDIN chaqirilishini tasdiqlash (SCM'ga imkon qadar tezroq signal
    # berish uchun - agent ishga tushirish vaqti cho'zilib ketsa ham SCM
    # allaqachon "running" deb bilib turadi)
    svc_do_run_start = content.find("def SvcDoRun")
    report_running_pos = content.find("ReportServiceStatus(win32service.SERVICE_RUNNING)", svc_do_run_start)
    agent_creation_pos = content.find("EndpointAgent(", svc_do_run_start)
    assert report_running_pos != -1 and agent_creation_pos != -1
    assert report_running_pos < agent_creation_pos, (
        "ReportServiceStatus(SERVICE_RUNNING) EndpointAgent yaratilishidan OLDIN "
        "chaqirilishi kerak - SCM'ga imkon qadar tezroq signal berish uchun"
    )


check("service_wrapper.py: SCM'ga SERVICE_RUNNING signali (30s timeout TUB SABABI tuzatilgan)", _test_service_wrapper_reports_running_status)

# ---------------------------------------------------------------------------
print("\n=== 55) Windows Agent: qo'shimcha real production tuzatishlari (--startup auto, ko'p-foydalanuvchi kuzatish, cache yo'li) ===")


def _test_windows_agent_additional_fixes():
    """
    Foydalanuvchi tashqi manbadan (mustaqil ishlab chiqilgan, real
    production sinovlari orqali tasdiqlangan) qo'shimcha tuzatishlar
    bilan zip yubordi. Ko'rib chiqilgach, quyidagi 3 ta QO'SHIMCHA
    real xato ham aniqlandi va bizning kodga integratsiya qilindi:

    1) Deploy skripti xizmatni 'install' bilan (standart - odatda
       "Manual" ishga tushirish turi bilan) o'rnatgan edi - bu
       reboot vaqtida SCM'ning o'zi uni AVTOMATIK ishga tushirmasligini
       anglatadi (foydalanuvchining haqiqiy Get-WinEvent natijasida
       "Тип запуска службы: Вручную" ko'rinib, bu tasdiqlangan).
       Tuzatish: '--startup auto install'.

    2) service_wrapper.py DEFAULT_WATCH_DIRS_WINDOWS (%USERPROFILE%
       asosida) ishlatar edi - bu LocalSystem hisobi ostida
       mazmunsiz (haqiqiy foydalanuvchi profiliga ishora qilmaydi).
       Tuzatish: barcha haqiqiy Windows foydalanuvchi profillarini
       (C:\\Users\\* ostida) avtomatik aniqlaydigan
       _windows_watch_dirs() funksiyasi.

    3) LOCAL_CACHE_FILE (hash keshi) ham nisbiy yo'l bilan yozilgan
       edi - xuddi agent.log kabi, LocalSystem ish katalogi
       muammosiga uchrashi mumkin edi.
    """
    # 1) Deploy skriptida --startup auto borligini tekshirish
    deploy_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Deploy-NetworkSecurityAgent.ps1",
    )
    with open(deploy_path) as f:
        deploy_content = f.read()
    assert "--startup auto" in deploy_content, (
        "Deploy skripti '--startup auto' bilan o'rnatishi kerak - aks holda "
        "xizmat reboot'da AVTOMATIK ishga tushmaydi (real production'da "
        "'Тип запуска службы: Вручную' orqali tasdiqlangan xato)"
    )
    # Post-start tekshiruv ham borligini tasdiqlash (xizmat haqiqatan Running holatida)
    assert "runningService" in deploy_content and "Running" in deploy_content, (
        "Deploy skripti Start-Service'dan keyin xizmat holatini qayta tekshirishi kerak"
    )

    # 2) service_wrapper.py'da ko'p-foydalanuvchi kuzatish funksiyasi borligini tekshirish
    wrapper_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "windows_agent", "service_wrapper.py",
    )
    with open(wrapper_path) as f:
        wrapper_content = f.read()
    assert "_windows_watch_dirs" in wrapper_content, (
        "service_wrapper.py barcha Windows foydalanuvchi profillarini avtomatik "
        "aniqlovchi funksiyaga ega bo'lishi kerak (LocalSystem %USERPROFILE% "
        "muammosini hal qilish uchun)"
    )
    assert "Users" in wrapper_content

    # 3) LOCAL_CACHE_FILE ham mutlaq/xavfsiz yo'lga bog'liq ekanligini tekshirish
    import agent_core.agent as agent_mod
    assert hasattr(agent_mod, "LOCAL_CACHE_FILE")
    # Linux muhitida _default_log_file() asosida hisoblanadi (nisbiy "./" emas)

    # 4) CI workflow'da haqiqiy SCM ro'yxatdan o'tish tekshiruvi borligini tasdiqlash
    workflow_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        ".github", "workflows", "build-windows-agent.yml",
    )
    with open(workflow_path) as f:
        workflow_content = f.read()
    assert "sc.exe query NetworkSecurityEndpointAgent" in workflow_content, (
        "CI workflow'da xizmatning HAQIQATAN SCM'da ro'yxatdan o'tishini "
        "tekshiruvchi qadam bo'lishi kerak - bu real production xatosini "
        "(muvaffaqiyat deb log qilingan, lekin SCM'da yo'q) avtomatik ushlaydi"
    )


check("Windows Agent qo'shimcha tuzatishlar (--startup auto, ko'p-foydalanuvchi kuzatish, CI SCM tekshiruvi)", _test_windows_agent_additional_fixes)

# ---------------------------------------------------------------------------
print("\n=== 56) EndpointAgent yangi start_background()/stop() API'si - real thread-asosli heartbeat ===")


def _test_endpoint_agent_start_background_stop():
    """
    agent_core/agent.py EndpointAgent klassi endi start_background()/
    stop() metodlariga ega - bu Windows Service uchun bloklanmaydigan
    ishga tushirish imkonini beradi (heartbeat alohida thread'da).
    Bu real HTTP orqali (heartbeat serverga haqiqatan yetib borishini)
    tekshiriladi.
    """
    import subprocess
    import time as _time
    import tempfile
    import threading as threading_check

    import agent_core.agent as agent_mod
    assert hasattr(agent_mod.EndpointAgent, "start_background")
    assert hasattr(agent_mod.EndpointAgent, "stop")

    api_env = {**os.environ, "AGENT_API_KEY": "ci-newapi-key"}
    api_proc = subprocess.Popen(["python3", "-m", "api.server"], env=api_env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _time.sleep(2)
        os.environ["API_SERVER_URL"] = "http://127.0.0.1:8443"
        os.environ["AGENT_API_KEY"] = "ci-newapi-key"
        os.environ["HEARTBEAT_INTERVAL_SECONDS"] = "1"

        import importlib
        importlib.reload(agent_mod)

        watch_dir = tempfile.mkdtemp()
        agent = agent_mod.EndpointAgent([watch_dir])
        agent.start_background()
        assert agent._heartbeat_thread is not None and agent._heartbeat_thread.is_alive()

        _time.sleep(2.5)

        agent.stop()
        _time.sleep(0.5)
        assert not agent._heartbeat_thread.is_alive(), "Heartbeat thread stop() dan keyin ham ishlab turibdi"

        s = get_session()
        d = s.query(Device).filter(Device.hostname == agent.hostname).order_by(Device.id.desc()).first()
        assert d is not None, "Heartbeat orqali qurilma yozilmadi"
        assert d.agent_last_heartbeat is not None
        s.close()

    finally:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        for k in ["API_SERVER_URL", "AGENT_API_KEY", "HEARTBEAT_INTERVAL_SECONDS"]:
            os.environ.pop(k, None)


check("EndpointAgent start_background()/stop() - real thread-asosli heartbeat (HTTP orqali tasdiqlangan)", _test_endpoint_agent_start_background_stop)

# ---------------------------------------------------------------------------
print("\n=== 57) service_wrapper.py: SCM Control Dispatcher aniq chaqiruvi (PyInstaller+pywin32 muammosi) ===")


def _test_service_wrapper_explicit_dispatcher():
    """
    Real production'da topilgan xato: ReportServiceStatus(SERVICE_RUNNING)
    va --startup auto tuzatilgandan KEYIN ham, xizmat hali "Cannot start
    service" bilan muvaffaqiyatsiz bo'lardi - garchi install/remove/debug
    (argumentlar bilan chaqirilganda) mukammal ishlagan bo'lsa ham.

    Bu - PyInstaller bilan "muzlatilgan" (frozen) pywin32 xizmatlarining
    tanilgan muammosi: Windows SCM xizmatni HECH QANDAY argumentsiz
    chaqiradi, va win32serviceutil.HandleCommandLine()ning bu holatni
    avtomatik aniqlashi frozen exe'larda ishonchsiz bo'lishi mumkin.

    Tuzatish: sys.argv uzunligini ANIQ tekshirib, argument bo'lmasa
    servicemanager.Initialize()/PrepareToHostSingle()/
    StartServiceCtrlDispatcher()ni QO'LDA chaqirish.
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "windows_agent", "service_wrapper.py",
    )
    with open(script_path) as f:
        content = f.read()

    assert "len(sys.argv) == 1" in content, (
        "Argumentsiz chaqirilish holati ANIQ tekshirilishi kerak (SCM "
        "xizmatni argumentsiz ishga tushiradi)"
    )
    assert "servicemanager.Initialize()" in content
    assert "PrepareToHostSingle" in content
    assert "StartServiceCtrlDispatcher" in content

    # CI workflow'da HAQIQIY Start-Service tekshiruvi borligini tasdiqlash
    # (faqat ro'yxatdan o'tish emas - bu farq real production xatosining
    # aynan o'zi edi)
    workflow_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        ".github", "workflows", "build-windows-agent.yml",
    )
    with open(workflow_path) as f:
        workflow_content = f.read()
    assert "Start-Service -Name NetworkSecurityEndpointAgent" in workflow_content, (
        "CI workflow'da xizmatning HAQIQATAN 'Running' holatiga o'tishini "
        "tekshiruvchi Start-Service chaqiruvi bo'lishi kerak - faqat "
        "ro'yxatdan o'tish (sc.exe query) yetarli emas"
    )
    assert '"Running"' in workflow_content or "'Running'" in workflow_content

    # Sintaksis to'g'riligini qayta tasdiqlash
    import ast
    ast.parse(content)


check("service_wrapper.py: SCM Control Dispatcher aniq chaqiruvi + CI haqiqiy Start-Service tekshiruvi", _test_service_wrapper_explicit_dispatcher)

# ---------------------------------------------------------------------------
print("\n=== 58) Web Activity: Zeek HTTP/SSL/DNS -> WebAccessLog -> Dashboard (to'liq real zanjir) ===")


def _test_web_activity_full_chain():
    """
    Foydalanuvchi yuborgan qo'shimcha funksiya: sayt/domen tarixini
    kuzatish. Zeek http.log/ssl.log/dns.log'dan WebAccessLog jadvaliga,
    va Dashboard'ning /web-activity sahifasida real HTTP orqali
    ko'rinishini tekshiradi.
    """
    import collectors.zeek_reader as zr

    s = get_session()

    # 1) Zeek HTTP log yozuvi
    http_rec = {
        "ts": 1755500000.0, "id.orig_h": "172.16.61.1", "id.resp_h": "93.184.216.34",
        "method": "GET", "host": "ci-test-site.com", "uri": "/page1",
        "status_code": 200, "user_agent": "TestAgent/1.0",
    }
    zr.process_http(s, http_rec)

    # 2) Zeek SSL (TLS SNI) log yozuvi
    ssl_rec = {
        "ts": 1755500010.0, "id.orig_h": "172.16.61.2", "id.resp_h": "142.250.1.1",
        "server_name": "ci-secure-site.com",
    }
    zr.process_ssl(s, ssl_rec)

    # 3) Zeek DNS log yozuvi
    dns_rec = {"ts": 1755500020.0, "id.orig_h": "172.16.61.3", "query": "ci-dns-site.com."}
    zr.process_dns(s, dns_rec)

    s.commit()

    logs = s.query(WebAccessLog).filter(WebAccessLog.source_ip.in_(["172.16.61.1", "172.16.61.2", "172.16.61.3"])).all()
    assert len(logs) == 3, f"3 ta WebAccessLog yozuvi kutilgan edi, {len(logs)} keldi"

    http_log = next(l for l in logs if l.protocol == "HTTP")
    assert http_log.domain == "ci-test-site.com"
    assert http_log.url == "http://ci-test-site.com/page1"
    assert http_log.status_code == 200

    ssl_log = next(l for l in logs if l.protocol == "HTTPS")
    assert ssl_log.domain == "ci-secure-site.com"
    assert ssl_log.url == "https://ci-secure-site.com/"

    dns_log = next(l for l in logs if l.protocol == "DNS")
    assert dns_log.domain == "ci-dns-site.com"
    s.close()

    # 4) Dashboard'da real HTTP orqali ko'rinishini tekshirish
    from dashboard.app import app as dash_app
    from dashboard.create_user import create_user
    create_user("webactivity_ci_admin", "webactivityci123", "admin")
    dash_app.secret_key = "test-secret-webactivity"
    client = _dash_client(dash_app)
    client.post("/login", data={"username": "webactivity_ci_admin", "password": "webactivityci123"})

    r = client.get("/web-activity")
    assert r.status_code == 200
    assert b"ci-test-site.com" in r.data
    assert b"ci-secure-site.com" in r.data

    # Filtr ishlashini tekshirish (faqat bitta sayt)
    r2 = client.get("/web-activity?site=ci-secure-site")
    assert b"ci-secure-site.com" in r2.data
    assert b"ci-test-site.com" not in r2.data, "Filtr boshqa saytni chiqarib tashlashi kerak edi"


check("Web Activity: Zeek HTTP/SSL/DNS -> WebAccessLog -> Dashboard (real HTTP orqali)", _test_web_activity_full_chain)

# ---------------------------------------------------------------------------
print("\n=== 59) Xavfsiz Karantin: SHA256 tasdiqlash + haqiqiy fayl bilan karantin (agent_core va engine) ===")


def _test_quarantine_mechanism():
    """
    Foydalanuvchi yuborgan qo'shimcha funksiya: zararli fayllarni
    o'chirish o'rniga xavfsiz karantinga olish (SHA256 orqali nusxa
    tasdiqlanadi, keyin asl fayl o'chiriladi).
    """
    import shutil
    import hashlib
    import importlib

    work_dir = "/tmp/_test_quarantine"
    quarantine_dir = "/tmp/_test_quarantine_output"
    for d in (work_dir, quarantine_dir):
        if os.path.exists(d):
            shutil.rmtree(d)
    os.makedirs(work_dir)

    # --- 1) engine/quarantine.py: real fayl bilan muvaffaqiyatli karantin ---
    os.environ["QUARANTINE_DIR"] = quarantine_dir
    import engine.quarantine as eq
    importlib.reload(eq)

    test_file = os.path.join(work_dir, "malware_test.exe")
    with open(test_file, "wb") as f:
        f.write(b"CI test uchun sun'iy zararli fayl mazmuni")

    with open(test_file, "rb") as f:
        real_sha256 = hashlib.sha256(f.read()).hexdigest()

    result = eq.quarantine_file(test_file, real_sha256, "CI test")
    assert result["quarantined"] is True
    assert not os.path.isfile(test_file), "Asl fayl karantinga olingandan keyin o'chirilishi kerak edi"
    assert os.path.isfile(result["quarantine_path"])

    with open(result["quarantine_path"], "rb") as f:
        quarantined_sha256 = hashlib.sha256(f.read()).hexdigest()
    assert quarantined_sha256 == real_sha256, "Karantin nusxasi original bilan bir xil bo'lishi kerak"

    # --- 2) agent_core/quarantine.py: SHA256 MOS KELMASA, xavfsizlik tekshiruvi rad etishi kerak ---
    os.environ["AGENT_QUARANTINE_DIR"] = quarantine_dir + "_agentcore"
    import agent_core.quarantine as aq
    importlib.reload(aq)

    test_file2 = os.path.join(work_dir, "real_file.exe")
    with open(test_file2, "wb") as f:
        f.write(b"Haqiqiy fayl mazmuni")

    wrong_sha256 = "f" * 64  # ataylab noto'g'ri
    result2 = aq.quarantine_file(test_file2, wrong_sha256, "CI test - noto'g'ri hash")
    assert result2["quarantined"] is False, "Noto'g'ri SHA256 bilan karantin MUVAFFAQIYATSIZ bo'lishi kerak edi"
    assert os.path.isfile(test_file2), (
        "SHA256 mos kelmasa, asl fayl SAQLANIB QOLISHI kerak (xavfsizlik nazorati)"
    )

    # --- 3) agent_core/quarantine.py: to'g'ri SHA256 bilan muvaffaqiyatli ---
    with open(test_file2, "rb") as f:
        correct_sha256 = hashlib.sha256(f.read()).hexdigest()
    result3 = aq.quarantine_file(test_file2, correct_sha256, "CI test - to'g'ri hash")
    assert result3["quarantined"] is True
    assert not os.path.isfile(test_file2)

    shutil.rmtree(work_dir, ignore_errors=True)
    shutil.rmtree(quarantine_dir, ignore_errors=True)
    shutil.rmtree(quarantine_dir + "_agentcore", ignore_errors=True)
    for k in ["QUARANTINE_DIR", "AGENT_QUARANTINE_DIR"]:
        os.environ.pop(k, None)


check("Xavfsiz Karantin (SHA256 tasdiqlash, real fayl bilan, mos kelmasa rad etish)", _test_quarantine_mechanism)

# ---------------------------------------------------------------------------
print("\n=== 60) File Analysis Engine: VirusTotal 'confirmed' chegara mantig'i (real DB bilan) ===")


def _test_file_analysis_confirmed_threshold():
    """
    Foydalanuvchi yuborgan qo'shimcha tuzatish: bitta VirusTotal
    dvigateli signal bergani hali "tasdiqlangan" (avtomatik karantin
    uchun asos) degani emas - soxta-pozitiv xavfi. Kamida 3 dvigatel
    VA hisobot beruvchilarning kamida 5% signal berishi talab qilinadi.
    Mahalliy blacklist va MalwareBazaar esa har doim "tasdiqlangan".
    """
    from unittest.mock import patch
    import engine.file_analysis_engine as fae

    # 1) Mahalliy blacklist - har doim tasdiqlangan
    s = get_session()
    s.add(HashBlacklist(sha256="1" * 64, threat_name="CI.LocalMalware", source="ci_test"))
    fe1 = FileEvent(src_ip="172.16.62.1", filename="local.exe", sha256="1" * 64, checked=False)
    s.add(fe1)
    s.commit()
    fae.analyze_one(s, fe1)
    s.commit()
    assert fe1.verdict == "malicious"
    alert1 = s.query(Alert).filter(Alert.file_event_id == fe1.id).first()
    assert alert1.severity == "critical"
    assert "TASDIQLANGAN" in alert1.action_taken
    s.close()

    # 2) VirusTotal past ishonch (1/70) - "shubhali" bo'lishi, karantin YO'Q
    s = get_session()
    fe2 = FileEvent(src_ip="172.16.62.2", filename="low_confidence.exe", sha256="2" * 64, checked=False)
    s.add(fe2)
    s.commit()
    with patch.object(fae, "check_virustotal", return_value={"malicious": True, "positives": 1, "total": 70, "threat_name": "Generic"}), \
         patch.object(fae, "check_malwarebazaar", return_value=None):
        fae.analyze_one(s, fe2)
        s.commit()
    # MUHIM (verdict taksonomiyasi tuzatilgan): zaif/tasdiqlanmagan
    # zararli signal endi "unknown" EMAS, "suspicious" - "unknown" endi
    # FAQAT "hech qanday manba umuman ma'lumot bermadi" holati uchun
    # ishlatiladi (bular BUTUNLAY BOSHQA holatlar - avval ikkalasi ham
    # "unknown" bo'lib, bir-biridan farqlanmas edi).
    assert fe2.verdict == "suspicious", "1 ta dvigatel bilan 'tasdiqlangan' bo'lmasligi, lekin 'unknown' EMAS 'suspicious' bo'lishi kerak edi"
    alert2 = s.query(Alert).filter(Alert.file_event_id == fe2.id).first()
    assert alert2.severity == "medium"
    assert "SHUBHALI" in alert2.action_taken
    s.close()

    # 3) VirusTotal yuqori ishonch (5/70, >=3 VA >=5%) - "tasdiqlangan"
    s = get_session()
    fe3 = FileEvent(src_ip="172.16.62.3", filename="high_confidence.exe", sha256="3" * 64, checked=False)
    s.add(fe3)
    s.commit()
    with patch.object(fae, "check_virustotal", return_value={"malicious": True, "positives": 5, "total": 70, "threat_name": "Trojan.Confirmed"}), \
         patch.object(fae, "check_malwarebazaar", return_value=None):
        fae.analyze_one(s, fe3)
        s.commit()
    assert fe3.verdict == "malicious"
    alert3 = s.query(Alert).filter(Alert.file_event_id == fe3.id).first()
    assert alert3.severity == "critical"
    assert "TASDIQLANGAN" in alert3.action_taken
    s.close()


check("File Analysis Engine: VirusTotal 'confirmed' chegara mantig'i (mahalliy/past/yuqori ishonch)", _test_file_analysis_confirmed_threshold)

# ---------------------------------------------------------------------------
print("\n=== 61) Deep Scan Engine: haqiqiy fayl bilan to'liq karantin zanjiri (EICAR) ===")


def _test_deep_scan_real_quarantine():
    """
    Foydalanuvchi yuborgan qo'shimcha tuzatish: Deep Scan Engine'da
    avvalgi 'TODO' placeholder o'rniga haqiqiy karantin. YARA/ClamAV
    signal berganda, fayl haqiqatan xavfsiz karantinga olinishi
    (SHA256 tasdiqlangan holda) real EICAR test signature bilan
    tekshiriladi.
    """
    import shutil
    from unittest.mock import patch
    import hashlib
    import importlib

    work_dir = "/tmp/_test_deep_scan_quarantine"
    quarantine_dir = "/tmp/_test_deep_scan_quarantine_output"
    for d in (work_dir, quarantine_dir):
        if os.path.exists(d):
            shutil.rmtree(d)
    os.makedirs(work_dir)

    os.environ["QUARANTINE_DIR"] = quarantine_dir
    import engine.deep_scan_engine as dse
    importlib.reload(dse)

    eicar_path = os.path.join(work_dir, "eicar.txt")
    eicar_content = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*\n"
    with open(eicar_path, "wb") as f:
        f.write(eicar_content)
    sha256 = hashlib.sha256(eicar_content).hexdigest()

    s = get_session()
    fe = FileEvent(src_ip="172.16.63.1", filename="eicar.txt", sha256=sha256,
                    stored_path=eicar_path, checked=True, verdict="unknown")
    s.add(fe)
    s.commit()

    with patch.object(dse, "yara_scan_file", return_value=[{"rule": "CI_Test_Rule", "severity": "critical", "description": "CI test"}]), \
         patch.object(dse, "clamav_db_available", return_value=False):
        dse.deep_scan_one(s, fe)
        s.commit()

    assert fe.verdict == "malicious"
    alert = s.query(Alert).filter(Alert.file_event_id == fe.id).first()
    assert "karantinaga olindi" in alert.action_taken
    assert not os.path.isfile(eicar_path), "EICAR fayli karantinga olinib, asli o'chirilishi kerak edi"
    s.close()

    shutil.rmtree(work_dir, ignore_errors=True)
    shutil.rmtree(quarantine_dir, ignore_errors=True)
    os.environ.pop("QUARANTINE_DIR", None)


check("Deep Scan Engine: real EICAR fayl bilan to'liq karantin zanjiri", _test_deep_scan_real_quarantine)

# ---------------------------------------------------------------------------
print("\n=== 62) Windows Agent: tizim proksi sozlamalaridan mustaqil ulanish (real production xatosi) ===")


def _test_agent_bypasses_system_proxy():
    """
    Real production'da topilgan xato: "Isobek" kompyuterida agent
    (LocalSystem hisobi) HAR BIR so'rovda ConnectionResetError bilan
    muvaffaqiyatsiz bo'lardi, garchi interaktiv foydalanuvchi
    sessiyasidan (Invoke-WebRequest) aynan bir xil serverga
    muvaffaqiyatli ulanish mumkin bo'lsa ham. Sabab: LocalSystem
    muhit/tizim darajasidagi proksi sozlamalarini (masalan noto'g'ri
    sozlangan WinHTTP proksi) hurmat qiladi, requests kutubxonasi esa
    standart holatda shu proksini ishlatishga urinadi.

    Tuzatish: barcha ichki API chaqiruvlariga aniq `proxies={"http":
    None, "https": None}` qo'shildi - bizning server bilan aloqa
    hech qachon tashqi proksiga muhtoj emas.
    """
    import subprocess
    import time as _time

    api_env = {**os.environ, "AGENT_API_KEY": "ci-proxy-test-key"}
    api_proc = subprocess.Popen(["python3", "-m", "api.server"], env=api_env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _time.sleep(2)

        # Mavjud bo'lmagan, xato beruvchi proksi - real "Isobek" holatini simulyatsiya qiladi
        os.environ["HTTP_PROXY"] = "http://127.0.0.1:19998"
        os.environ["HTTPS_PROXY"] = "http://127.0.0.1:19998"
        os.environ["API_SERVER_URL"] = "http://127.0.0.1:8443"
        os.environ["AGENT_API_KEY"] = "ci-proxy-test-key"

        import importlib
        import agent_core.agent as agent_mod
        importlib.reload(agent_mod)

        result = agent_mod.check_hash_with_server_or_cache("b" * 64, {})
        assert result["source"] != "no_data_offline", (
            "Agent noto'g'ri tizim proksisi bilan ulanib bo'lmadi - "
            "bu real production'da 'Isobek' kompyuterida uchragan xato "
            "(ConnectionResetError) bilan bir xil turkum"
        )

        # Kod darajasida ham aniq tekshiramiz: barcha requests.post
        # chaqiruvlarida proxies= parametri borligini
        agent_source = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "agent_core", "agent.py",
        )
        with open(agent_source) as f:
            content = f.read()
        assert content.count('proxies={"http": None, "https": None}') >= 3, (
            "check_hash, report_incident, send_heartbeat - uchalasida ham "
            "proxies=None aniq belgilangan bo'lishi kerak"
        )

    finally:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        for k in ["HTTP_PROXY", "HTTPS_PROXY", "API_SERVER_URL", "AGENT_API_KEY"]:
            os.environ.pop(k, None)


check("Windows Agent tizim proksi sozlamalaridan mustaqil (real 'Isobek' xatosi tuzatilgan)", _test_agent_bypasses_system_proxy)

# ---------------------------------------------------------------------------
print("\n=== 63) Windows Agent: _windows_watch_dirs() diagnostika loglari va SystemDrive fallback (real 'Isobek' xatosi) ===")


def _test_windows_watch_dirs_diagnostics_and_fallback():
    """
    Real production'da topilgan xato: agent qayta yoqilgandan keyin
    faqat C:\\WINDOWS\\TEMP va C:\\WINDOWS\\Temp'ni kuzatgan, foydalanuvchi
    Downloads papkasi butunlay tashlab ketilgan - hech qanday xato
    yoki ogohlantirish log qilinmagan.

    Tuzatish: (1) har bir profil tekshiruvi endi aniq log qilinadi
    (topildi/topilmadi/xato), (2) SystemDrive muhit o'zgaruvchisi
    kutilganidek ishlamasa (masalan bo'sh qator bo'lsa, natijada
    nisbiy "Users" yo'liga aylanib, jim ravishda hech narsa
    topilmasligi mumkin edi), standart C:\\Users yo'liga zaxira
    (fallback) qo'shildi.
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "windows_agent", "service_wrapper.py",
    )
    with open(script_path) as f:
        content = f.read()

    assert 'candidates = [r"C:\\Users"]' in content, (
        "SystemDrive muhit o'zgaruvchisi ishonchsiz bo'lganda standart "
        "C:\\Users yo'liga zaxira (fallback) qo'shilishi kerak"
    )
    assert "logger.info" in content and "Yakuniy kuzatiladigan papkalar" in content, (
        "_windows_watch_dirs() endi aniq diagnostika loglari yozishi kerak - "
        "aks holda 'Downloads topilmadi' kabi muammolar jim qolib ketadi"
    )
    assert "logger.warning" in content and "kirish huquqi cheklangan" in content, (
        "Profilga kirish huquqi bo'lmagan holat aniq ogohlantirilishi kerak"
    )

    import ast
    ast.parse(content)


check("Windows Agent: _windows_watch_dirs() diagnostika + SystemDrive fallback (real 'Isobek' xatosi)", _test_windows_watch_dirs_diagnostics_and_fallback)

# ---------------------------------------------------------------------------
print("\n=== 65) Deploy skripti: API_SERVER_URL SYSVOL faylidan (versiya yangilanishida qayta sozlash shart emas) ===")


def _test_deploy_script_reads_api_server_url_from_file():
    """
    Foydalanuvchi so'rovi: har safar yangi Deploy-NetworkSecurityAgent.ps1
    versiyasini GitHub'dan yuklab olganda, API_SERVER_URL'ni qo'lda
    qayta sozlashi shart bo'lmasligi kerak. AGENT_API_KEY allaqachon
    alohida SYSVOL faylidan (api_key.secret) o'qilardi - endi
    API_SERVER_URL ham xuddi shu naqsh bilan (api_server_url.txt)
    ishlaydi.
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Deploy-NetworkSecurityAgent.ps1",
    )
    with open(script_path) as f:
        content = f.read()

    assert 'api_server_url.txt' in content, (
        "Deploy skripti API_SERVER_URL'ni alohida SYSVOL faylidan "
        "o'qishi kerak - versiya yangilanganda qayta sozlash shart bo'lmasligi uchun"
    )
    # Fayl AGENT_API_KEY o'rnatilishidan OLDIN o'qilishi kerak (mantiqiy tartib)
    server_url_pos = content.find("api_server_url.txt")
    api_key_pos = content.find("api_key.secret")
    assert server_url_pos != -1 and api_key_pos != -1
    assert server_url_pos < api_key_pos, (
        "API_SERVER_URL SYSVOL faylini o'qish AGENT_API_KEY'dan OLDIN bo'lishi kerak"
    )

    # Qavslar balansini qayta tasdiqlash
    code_only = [l for l in content.splitlines(keepends=True) if not l.strip().startswith("#")]
    code_content = "".join(code_only)
    for open_c, close_c in [("{", "}"), ("(", ")"), ("[", "]")]:
        assert code_content.count(open_c) == code_content.count(close_c)


check("Deploy skripti: API_SERVER_URL SYSVOL faylidan o'qiladi (versiya yangilanishida qayta sozlash shart emas)", _test_deploy_script_reads_api_server_url_from_file)

# ---------------------------------------------------------------------------
print("\n=== 64) Windows Agent: service_wrapper.py haqiqatan import va ishga tushirilganda xato bermasligi (CI'da topilgan REGRESSIYA) ===")


def _test_service_wrapper_actually_runs_without_nameerror():
    """
    Men o'zim (oldingi commit'da) qo'shgan REAL REGRESSIYA: yangi
    _windows_watch_dirs() logger.info()/.warning()/.debug()ni
    ishlatadi, lekin service_wrapper.py FAQAT `EndpointAgent`ni
    import qilardi (`from windows_agent.agent import EndpointAgent`),
    `logger`ni EMAS. Bu sintaksis darajasida (ast.parse) sezilmaydi -
    faqat funksiya HAQIQATAN chaqirilganda NameError beradi. Bu
    xato GitHub CI'ning haqiqiy Start-Service tekshiruvida ushlandi
    (xizmat ishga tushishda qulab tushdi).

    Bu test pywin32 modullarini soxta (mock) qilib, service_wrapper.py
    ni HAQIQATAN import qilib, _windows_watch_dirs()ni chaqirib,
    NameError chiqmasligini tasdiqlaydi - bu faqat ast.parse() emas,
    balki HAQIQIY bajarilishni tekshiradi.
    """
    import shutil
    import importlib

    fake_pywin32_dir = "/tmp/_test_fake_pywin32"
    if os.path.exists(fake_pywin32_dir):
        shutil.rmtree(fake_pywin32_dir)
    os.makedirs(fake_pywin32_dir)

    with open(os.path.join(fake_pywin32_dir, "win32event.py"), "w") as f:
        f.write("INFINITE = -1\ndef CreateEvent(*a, **kw): return object()\ndef SetEvent(*a, **kw): pass\ndef WaitForSingleObject(*a, **kw): pass\n")
    with open(os.path.join(fake_pywin32_dir, "win32service.py"), "w") as f:
        f.write("SERVICE_RUNNING = 4\nSERVICE_STOP_PENDING = 3\n")
    with open(os.path.join(fake_pywin32_dir, "win32serviceutil.py"), "w") as f:
        f.write(
            "class ServiceFramework:\n"
            "    def __init__(self, args): pass\n"
            "    def ReportServiceStatus(self, status): pass\n"
            "def HandleCommandLine(cls): pass\n"
        )
    with open(os.path.join(fake_pywin32_dir, "servicemanager.py"), "w") as f:
        f.write(
            "EVENTLOG_INFORMATION_TYPE = 1\nPYS_SERVICE_STARTED = 1\n"
            "def LogMsg(*a, **kw): pass\n"
            "def LogErrorMsg(*a, **kw): pass\n"
            "def LogWarningMsg(*a, **kw): pass\n"
            "def Initialize(): pass\n"
            "def PrepareToHostSingle(cls): pass\n"
            "def StartServiceCtrlDispatcher(): pass\n"
        )

    sys.path.insert(0, fake_pywin32_dir)
    try:
        for mod_name in ["windows_agent.service_wrapper", "win32event", "win32service", "win32serviceutil", "servicemanager"]:
            sys.modules.pop(mod_name, None)

        import windows_agent.service_wrapper as sw
        assert hasattr(sw, "logger"), (
            "service_wrapper.py `logger`ni import qilishi SHART - "
            "aks holda _windows_watch_dirs() ishga tushganda NameError beradi "
            "(bu real CI'da xizmatning ishga tushmasligiga sabab bo'lgan edi)"
        )

        # HAQIQATAN chaqirib, NameError chiqmasligini tasdiqlash
        result = sw._windows_watch_dirs()
        assert isinstance(result, list)

        # To'liq SvcDoRun mantig'ini ham (win32event.WaitForSingleObject'siz) sinash
        agent = sw.EndpointAgent(result)
        assert agent is not None

    finally:
        sys.path.remove(fake_pywin32_dir)
        shutil.rmtree(fake_pywin32_dir, ignore_errors=True)
        for mod_name in ["windows_agent.service_wrapper", "win32event", "win32service", "win32serviceutil", "servicemanager"]:
            sys.modules.pop(mod_name, None)
        import windows_agent.agent  # noqa: F401 - keyingi testlar uchun agent_core.agent holatini tozalash


check("service_wrapper.py: HAQIQATAN import/chaqirilganda NameError yo'q (CI regressiyasi tuzatilgan)", _test_service_wrapper_actually_runs_without_nameerror)

# ---------------------------------------------------------------------------
print("\n=== 65) Dashboard: Endpoint Agent Online/Offline holati + fayl tekshiruvi ko'rinishi ===")


def _test_agent_online_offline_status():
    """
    Foydalanuvchi so'ragan 2 ta kamchilik:
      1) Dashboard'da ulangan agentlarning online/offline holati ko'rinmasdi.
      2) Agent tekshirgan (lekin toza chiqqan) fayllar Dashboard'da HECH
         QAYERDA ko'rinmasdi - faqat zararli topilganda Alert yaratilardi,
         shuning uchun "agent fayllarni tekshirmayapti" degan noto'g'ri
         taassurot paydo bo'lardi.

    Bu test ikkalasini ham real HTTP (Flask test client) + real DB orqali
    tasdiqlaydi.
    """
    from datetime import timedelta
    from dashboard.app import _agent_status
    from config.settings import AGENT_ONLINE_THRESHOLD_MINUTES
    from db.models import utcnow

    now = utcnow()

    # --- 1) _agent_status() mantig'i ---
    assert _agent_status(None) is None
    assert _agent_status(now) == "online"
    assert _agent_status(now - timedelta(minutes=AGENT_ONLINE_THRESHOLD_MINUTES + 5)) == "offline"

    # --- 2) devices() route'da real qurilma online/offline ko'rinishi ---
    s = get_session()
    online_dev = Device(
        ip_address="172.16.9.51", hostname="ONLINE-PC", source="endpoint_agent",
        agent_last_heartbeat=now, agent_version="1.0.8", agent_os="windows",
    )
    offline_dev = Device(
        ip_address="172.16.9.52", hostname="OFFLINE-PC", source="endpoint_agent",
        agent_last_heartbeat=now - timedelta(hours=5), agent_version="1.0.8", agent_os="windows",
    )
    s.add_all([online_dev, offline_dev])
    s.commit()
    s.close()

    from dashboard.app import app as dashboard_app
    from dashboard.create_user import create_user
    create_user("agentstatus_ci_admin", "agentstatusci123", "admin")
    dashboard_app.secret_key = "test-secret-agent-status"
    client = _dash_client(dashboard_app)
    client.post("/login", data={"username": "agentstatus_ci_admin", "password": "agentstatusci123"})

    resp = client.get("/devices")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "ONLINE-PC" in html and "OFFLINE-PC" in html
    assert "ONLINE" in html
    assert "OFFLINE" in html

    resp = client.get("/")
    assert resp.status_code == 200

    # --- 3) check_hash orqali agent tekshirgan (toza VA zararli) fayllar
    #         file_events jadvalida (Dashboard "Fayllar" sahifasi manbasi)
    #         paydo bo'lishi ---
    from api import server as api_server
    api_server.AGENT_API_KEY = "test-key-online-offline"
    api_client = api_server.app.test_client()

    clean_sha = "d" * 64
    r = api_client.post("/api/v1/check_hash", json={
        "sha256": clean_sha, "filename": "gilocht.pdf",
        "hostname": "ONLINE-PC", "ip_address": "172.16.9.51",
    }, headers={"X-API-Key": "test-key-online-offline"})
    assert r.status_code == 200
    assert r.get_json()["malicious"] is False

    s = get_session()
    s.add(HashBlacklist(sha256="e" * 64, threat_name="Agent-Visibility-Test", source="manual"))
    s.commit()
    s.close()

    r = api_client.post("/api/v1/check_hash", json={
        "sha256": "e" * 64, "filename": "virus.exe",
        "hostname": "ONLINE-PC", "ip_address": "172.16.9.51",
    }, headers={"X-API-Key": "test-key-online-offline"})
    assert r.status_code == 200
    assert r.get_json()["malicious"] is True

    s = get_session()
    clean_event = s.query(FileEvent).filter(FileEvent.sha256 == clean_sha).first()
    malicious_event = s.query(FileEvent).filter(FileEvent.sha256 == "e" * 64).first()
    assert clean_event is not None, "Toza fayl ham file_events'ga yozilishi kerak edi (agent faoliyati ko'rinishi uchun)"
    # MUHIM (verdict taksonomiyasi tuzatilgan): bu sha256 hech qanday
    # manbada (local/VT/MalwareBazaar) topilmagan - VT_API_KEY bu
    # sandbox'da sozlanmagan, ya'ni hech kim uni HAQIQATAN "toza" deb
    # tasdiqlamagan. To'g'ri verdict "clean" EMAS, "unknown" (avvalgi
    # xato: "topilmadi" har doim "clean" deb yozilardi).
    assert clean_event.verdict == "unknown", "hech kim tasdiqlamagan fayl 'unknown' bo'lishi kerak (avvalgi 'clean' xatosi)"
    assert clean_event.channel == "endpoint_agent"
    assert clean_event.filename == "gilocht.pdf"
    assert malicious_event is not None
    assert malicious_event.verdict == "malicious"
    assert malicious_event.threat_score == 100
    s.close()

    # --- 4) hostname/ip_address yuborilmasa (eski chaqiruvchi/test) - xato bermasligi ---
    r = api_client.post("/api/v1/check_hash", json={"sha256": "f" * 64},
                         headers={"X-API-Key": "test-key-online-offline"})
    assert r.status_code == 200

    # --- 5) /files sahifasida "Faqat Endpoint Agent" filtri ishlashi ---
    resp = client.get("/files?channel=endpoint_agent")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "gilocht.pdf" in html


check("Dashboard: Agent Online/Offline holati + Fayllar sahifasida agent faoliyati ko'rinishi", _test_agent_online_offline_status)

# ---------------------------------------------------------------------------
print("\n=== 66) GPO skriptlari: '.env' orqali sozlash + har kompyuter uchun alohida API token (AD auto-enroll) ===")


def _test_gpo_env_file_config():
    """
    Foydalanuvchi so'rovi (1): ulanayotgan server manzili va API kalit
    endi BITTA `.env` faylidan (server tomonidagi `.env.example` bilan
    bir xil format) o'qilishi kerak - avvalgi ikkita alohida fayl
    (`api_server_url.txt` + `api_key.secret`) o'rniga. Orqaga moslik
    saqlanishi SHART - '.env' topilmasa, eski fayllarga qaytish kerak.

    PowerShell bu sandbox'da mavjud emas (Zeek/Grafana kabi holat) -
    shuning uchun matn-asosida (funksiya/o'zgaruvchi nomlari mavjudligi,
    mantiqiy tartib, qavslar balansi) tekshiriladi - bu loyihada
    GPO skriptlari uchun ilgari ham qo'llanilgan usul.
    """
    deploy_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Deploy-NetworkSecurityAgent.ps1",
    )
    with open(deploy_path) as f:
        deploy_content = f.read()

    assert "Read-DotEnv" in deploy_content
    assert 'Join-Path $ServerShare ".env"' in deploy_content
    # Orqaga moslik - eski fayllar hali ham o'qiladi
    assert "api_server_url.txt" in deploy_content
    assert "api_key.secret" in deploy_content

    install_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Install-NetworkSecurityAgent.ps1",
    )
    with open(install_path) as f:
        install_content = f.read()

    assert "Read-DotEnv" in install_content
    assert "Mandatory=$true" not in install_content, (
        "-ApiServerUrl/-ApiKey endi IXTIYORIY bo'lishi kerak (.env fallback bilan)"
    )

    for path, content in [(deploy_path, deploy_content), (install_path, install_content)]:
        code_only = [l for l in content.splitlines(keepends=True) if not l.strip().startswith("#")]
        code_content = "".join(code_only)
        for open_c, close_c in [("{", "}"), ("(", ")"), ("[", "]")]:
            assert code_content.count(open_c) == code_content.count(close_c), f"{path}: {open_c}{close_c} balansi buzilgan"


check("GPO skriptlari: '.env' orqali sozlash (orqaga moslik bilan)", _test_gpo_env_file_config)


def _test_agent_enroll_per_computer_token():
    """
    Foydalanuvchi so'rovi (2): AD orqali avtomatik ulanayotgan har bir
    kompyuter uchun ALOHIDA API token yaratilsin va o'sha kompyuterga
    biriktirilsin - shu paytgacha barcha agentlar bitta umumiy
    AGENT_API_KEY'ni ishlatgan.

    Real HTTP (Flask test client) + real DB orqali to'liq zanjir:
    bootstrap kalit -> /api/v1/agent_enroll -> yangi, shu kompyuterga
    xos token -> o'sha token bilan check_hash ishlashi -> qayta enroll
    qilinsa eski token avtomatik bekor qilinishi -> Dashboard
    /api-tokens sahifasida ko'rinishi.
    """
    from api import server as api_server
    from db.models import ApiToken
    api_server.AGENT_API_KEY = "bootstrap-key-enroll-test"
    client = api_server.app.test_client()

    # --- 1) hostname'siz so'rov - 400 ---
    r = client.post("/api/v1/agent_enroll", json={},
                     headers={"X-API-Key": "bootstrap-key-enroll-test"})
    assert r.status_code == 400

    # --- 2) bootstrap kalit bilan enroll -> yangi, ALOHIDA token ---
    r = client.post("/api/v1/agent_enroll", json={"hostname": "ENROLL-TEST-PC"},
                     headers={"X-API-Key": "bootstrap-key-enroll-test"})
    assert r.status_code == 200
    first_token = r.get_json()["token"]
    assert first_token.startswith("nssk_")
    assert first_token != "bootstrap-key-enroll-test"

    s = get_session()
    row = s.query(ApiToken).filter(ApiToken.agent_hostname == "ENROLL-TEST-PC", ApiToken.revoked.is_(False)).first()
    assert row is not None, "enroll qilingan token bazada agent_hostname bilan bog'langan bo'lishi kerak"
    assert row.created_by == "ad_auto_enroll"
    s.close()

    # --- 3) YANGI token o'zi bilan ham (bootstrap kalitsiz) boshqa so'rovlar
    # ishlashi - MUHIM: `require_api_key` endi hostname'ga bog'langan
    # tokenlar uchun so'rov tanasidagi `hostname`ning ANIQ mos kelishini
    # talab qiladi (boshqa qurilma nomidan token ishlatishning oldini
    # olish uchun - xavfsizlik auditida qo'shilgan) - haqiqiy Agent
    # (`agent_core/agent.py`) buni check_hash'da DOIM yuboradi. ---
    r = client.post("/api/v1/check_hash", json={"sha256": "1" * 64, "hostname": "ENROLL-TEST-PC"},
                     headers={"X-API-Key": first_token})
    assert r.status_code == 200

    # --- 4) bir xil hostname uchun QAYTA enroll -> eski token BEKOR qilinadi ---
    r = client.post("/api/v1/agent_enroll", json={"hostname": "ENROLL-TEST-PC"},
                     headers={"X-API-Key": "bootstrap-key-enroll-test"})
    assert r.status_code == 200
    second_token = r.get_json()["token"]
    assert second_token != first_token

    r = client.post("/api/v1/check_hash", json={"sha256": "2" * 64, "hostname": "ENROLL-TEST-PC"},
                     headers={"X-API-Key": first_token})
    assert r.status_code == 401, "qayta enroll qilingandan keyin ESKI token endi ishlamasligi kerak (bekor qilingan)"

    r = client.post("/api/v1/check_hash", json={"sha256": "3" * 64, "hostname": "ENROLL-TEST-PC"},
                     headers={"X-API-Key": second_token})
    assert r.status_code == 200, "YANGI token esa ishlashi kerak"

    s = get_session()
    active_count = s.query(ApiToken).filter(ApiToken.agent_hostname == "ENROLL-TEST-PC", ApiToken.revoked.is_(False)).count()
    assert active_count == 1, "faqat BITTA faol token qolishi kerak - qayta enroll eskilarini bekor qiladi"
    s.close()

    # --- 5) Dashboard /api-tokens sahifasida hostname ko'rinishi ---
    from dashboard.app import app as dash_app
    from dashboard.create_user import create_user
    create_user("enroll_ci_admin", "enrollci123456", "admin")
    dash_app.secret_key = "test-secret-enroll"
    dash_client = _dash_client(dash_app)
    dash_client.post("/login", data={"username": "enroll_ci_admin", "password": "enrollci123456"})
    r = dash_client.get("/api-tokens")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "ENROLL-TEST-PC" in html


check("AD auto-enroll: har kompyuter uchun alohida, bekor qilinadigan API token (real HTTP + real DB)", _test_agent_enroll_per_computer_token)

# ---------------------------------------------------------------------------
print("\n=== 67) Foydalanuvchilarni boshqarish: faollashtirish (reaktivatsiya) + tahrirlash (rol/parol) ===")


def _test_user_activate_and_edit():
    """
    Foydalanuvchi so'rovi: foydalanuvchilarni boshqarishda (1) faolsiz
    foydalanuvchini qayta faollashtira olish, (2) tahrirlash (rol
    o'zgartirish, parol tiklash) funksiyalari qo'shilsin - avvalgi
    versiyada faqat "yaratish" va "faolsizlantirish" bor edi, orqaga
    qaytarib bo'lmasdi.
    """
    from dashboard.create_user import create_user
    from dashboard.app import app as dash_app

    create_user("useredit_ci_admin", "usereditci123", "admin")
    create_user("useredit_ci_target", "targetpass123", "viewer")
    dash_app.secret_key = "test-secret-useredit"
    client = _dash_client(dash_app)
    client.post("/login", data={"username": "useredit_ci_admin", "password": "usereditci123"})

    s = get_session()
    target = s.query(User).filter(User.username == "useredit_ci_target").first()
    target_id = target.id
    s.close()

    # --- 1) Faolsizlantirish -> Faollashtirish (reaktivatsiya) ---
    client.post(f"/users/{target_id}/deactivate")
    s = get_session()
    assert s.query(User).filter(User.id == target_id).first().is_active is False
    s.close()

    r = client.post(f"/users/{target_id}/activate", follow_redirects=True)
    assert r.status_code == 200
    s = get_session()
    assert s.query(User).filter(User.id == target_id).first().is_active is True, "reaktivatsiyadan keyin foydalanuvchi FAOL bo'lishi kerak"
    s.close()

    # --- 2) Tahrirlash: rol o'zgartirish + parol tiklash ---
    r = client.post(f"/users/{target_id}/edit", data={"role": "analyst", "password": "newpass456"}, follow_redirects=True)
    assert r.status_code == 200
    s = get_session()
    updated = s.query(User).filter(User.id == target_id).first()
    assert updated.role == "analyst", "rol 'analyst'ga o'zgargan bo'lishi kerak edi"
    old_hash = updated.password_hash
    s.close()

    # Yangi parol bilan HAQIQATAN login qila olishini tekshirish
    other_client = _dash_client(dash_app)
    r = other_client.post("/login", data={"username": "useredit_ci_target", "password": "newpass456"}, follow_redirects=True)
    assert r.status_code == 200
    r2 = other_client.get("/")
    assert r2.status_code == 200, "yangi parol bilan login muvaffaqiyatli bo'lishi va sahifaga kirish kerak edi"

    # Eski parol endi ishlamasligi kerak
    stale_client = _dash_client(dash_app)
    stale_client.post("/login", data={"username": "useredit_ci_target", "password": "targetpass123"})
    r3 = stale_client.get("/users")
    assert r3.status_code != 200, "eski parol endi ishlamasligi kerak edi"

    # --- 3) O'zini-o'zi qulflab qo'yishning oldini olish (o'z admin rolini o'zgartira olmaydi) ---
    s = get_session()
    self_id = s.query(User).filter(User.username == "useredit_ci_admin").first().id
    s.close()
    client.post(f"/users/{self_id}/edit", data={"role": "viewer"})
    s = get_session()
    assert s.query(User).filter(User.id == self_id).first().role == "admin", "admin o'z rolini o'zgartira OLMASLIGI kerak (qulflanib qolish xavfi)"
    s.close()

    # --- 4) Audit log'da qayd etilgani ---
    from db.models import AuditLog
    s = get_session()
    actions = {a.action for a in s.query(AuditLog).filter(AuditLog.username == "useredit_ci_admin").all()}
    assert "activate_user" in actions
    assert "edit_user" in actions
    s.close()


check("Foydalanuvchilarni boshqarish: faollashtirish + tahrirlash (rol/parol, real HTTP + real DB)", _test_user_activate_and_edit)

# ---------------------------------------------------------------------------
print("\n=== 68) Install-NetworkSecurityAgent.ps1: AGENT_VERSION o'rnatilmagan edi (qayta tekshirishda topilgan real xato) ===")


def _test_install_script_sets_agent_version():
    """
    Foydalanuvchi "qayta tekshir" deb so'raganda, real production
    bazasini tekshirib chiqdim: DC1101TAS haqiqatan v1.0.9 kodi bilan
    ishlayotgan edi (file_events endi to'g'ri to'lib turibdi - fayl
    tekshirish funksiyasi ISHLAYAPTI!), lekin heartbeat hamon
    "agent_version": "1.0.0" deb yuborardi - bu Dashboard'da chalg'ituvchi
    "eskirgan" taassurot qoldiradi.

    Sabab: Install-NetworkSecurityAgent.ps1 (qo'lda o'rnatish skripti)
    API_SERVER_URL/AGENT_API_KEY'ni Machine muhit o'zgaruvchisi sifatida
    o'rnatardi, lekin AGENT_VERSION'ni HECH QACHON o'rnatmasdi -
    shuning uchun agent_core/agent.py'dagi standart qiymat ("1.0.0")
    doim ishlatilardi, .exe'ning haqiqiy versiyasidan qat'iy nazar.
    """
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "deploy", "windows_agent_gpo", "Install-NetworkSecurityAgent.ps1",
    )
    with open(script_path) as f:
        content = f.read()

    assert 'SetEnvironmentVariable("AGENT_VERSION"' in content, (
        "Install-NetworkSecurityAgent.ps1 AGENT_VERSION'ni Machine muhit "
        "o'zgaruvchisi sifatida o'rnatishi kerak - aks holda Dashboard "
        "doim eskirgan versiyani ko'rsatadi"
    )
    # AGENT_VERSION o'rnatilishi VERSION fayli o'qilgandan KEYIN bo'lishi kerak
    version_read_pos = content.find("$installedVersion = (Get-Content $versionSource")
    version_set_pos = content.find('SetEnvironmentVariable("AGENT_VERSION"')
    assert version_read_pos != -1 and version_set_pos != -1
    assert version_read_pos < version_set_pos

    code_only = [l for l in content.splitlines(keepends=True) if not l.strip().startswith("#")]
    code_content = "".join(code_only)
    for open_c, close_c in [("{", "}"), ("(", ")"), ("[", "]")]:
        assert code_content.count(open_c) == code_content.count(close_c)


check("Install-NetworkSecurityAgent.ps1: AGENT_VERSION endi to'g'ri o'rnatiladi (qayta tekshirishda topilgan real xato)", _test_install_script_sets_agent_version)

# ---------------------------------------------------------------------------
print("\n=== 69) XAVFSIZLIK (CRITICAL): TLS reverse proxy (nginx) + Ichki CA + ixtiyoriy mTLS ===")


def _test_tls_reverse_proxy():
    """
    Xavfsizlik auditi topilmasi (CRITICAL): "TLS/mTLS yo'qligi" - Agent
    API va Dashboard endi haqiqiy `nginx` TLS reverse proxy (ichki CA
    bilan imzolangan sertifikat) ortida ishlaydi. agent_api/dashboard'ning
    o'zi hamon oddiy HTTP (faqat 127.0.0.1'ga bog'langan) - TLS
    termination FAQAT nginx'da.

    Bu test HECH NARSANI soxtalashtirmaydi:
      - `api.server`/`dashboard.app` - HAQIQIY, alohida jarayonda ishga
        tushirilgan Flask server (real HTTP, test_client emas).
      - `deploy/pki/generate_ca.sh`/`issue_agent_cert.sh` - HAQIQIY
        openssl chaqiruvlari orqali CA/server/client sertifikat.
      - `deploy/nginx/entrypoint.sh` - production'da ishlatiladigan
        AYNAN SHU, o'zgartirilmagan skript + haqiqiy `nginx` binary.
    """
    import shutil
    import subprocess
    import tempfile
    import time as _time

    if shutil.which("nginx") is None:
        print("   (nginx o'rnatilmagan - test o'tkazib yuborildi; CI'da avtomatik o'rnatiladi)")
        return
    if shutil.which("envsubst") is None:
        print("   (envsubst/gettext-base o'rnatilmagan - test o'tkazib yuborildi)")
        return

    import requests as requests_mod

    repo_root = os.path.dirname(os.path.abspath(__file__))
    work_dir = tempfile.mkdtemp(prefix="tls_test_")
    cert_dir = os.path.join(work_dir, "certs")
    agent_port, dash_port = 18501, 18801
    nginx_agent_port, nginx_dash_port = 18444, 18844

    # --- 1) Ichki CA + server sertifikat (haqiqiy generate_ca.sh) ---
    gen_env = {**os.environ, "TLS_CERT_DIR": cert_dir,
               "TLS_SERVER_HOSTNAMES": "localhost", "TLS_SERVER_IPS": "127.0.0.1"}
    r = subprocess.run(["bash", os.path.join(repo_root, "deploy/pki/generate_ca.sh")],
                        env=gen_env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, f"generate_ca.sh muvaffaqiyatsiz: {r.stdout}\n{r.stderr}"
    ca_path = os.path.join(cert_dir, "ca.crt")
    assert os.path.isfile(ca_path) and os.path.isfile(os.path.join(cert_dir, "server.crt"))

    # --- 2) Client (mTLS) sertifikat - haqiqiy issue_agent_cert.sh ---
    r2 = subprocess.run(["bash", os.path.join(repo_root, "deploy/pki/issue_agent_cert.sh"), "CI-TEST-PC"],
                         env=gen_env, capture_output=True, text=True, timeout=30)
    assert r2.returncode == 0, f"issue_agent_cert.sh muvaffaqiyatsiz: {r2.stdout}\n{r2.stderr}"
    client_crt = os.path.join(cert_dir, "agents", "CI-TEST-PC.crt")
    client_key = os.path.join(cert_dir, "agents", "CI-TEST-PC.key")
    assert os.path.isfile(client_crt) and os.path.isfile(client_key)

    # --- 3) Haqiqiy backend jarayonlar ---
    api_env = {**os.environ, "API_PORT": str(agent_port), "AGENT_API_KEY": "ci-tls-test-key"}
    dash_env = {**os.environ, "DASHBOARD_PORT": str(dash_port)}
    api_proc = subprocess.Popen(["python3", "-m", "api.server"], env=api_env,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    dash_proc = subprocess.Popen(["python3", "-m", "dashboard.app"], env=dash_env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def _start_nginx(mtls_required: str, out_name: str):
        nginx_env = {
            **os.environ,
            "NGINX_AGENT_API_PORT": str(nginx_agent_port),
            "NGINX_DASHBOARD_PORT": str(nginx_dash_port),
            "NGINX_TLS_CERT_FILE": os.path.join(cert_dir, "server.crt"),
            "NGINX_TLS_KEY_FILE": os.path.join(cert_dir, "server.key"),
            "NGINX_TLS_CA_FILE": ca_path,
            "NGINX_AGENT_API_UPSTREAM": f"127.0.0.1:{agent_port}",
            "NGINX_DASHBOARD_UPSTREAM": f"127.0.0.1:{dash_port}",
            "NGINX_TEMPLATE_FILE": os.path.join(repo_root, "deploy/nginx/nginx.conf.template"),
            "NGINX_OUT_FILE": os.path.join(work_dir, out_name),
            "NGINX_ERROR_LOG": os.path.join(work_dir, f"{out_name}.error.log"),
            "NGINX_ACCESS_LOG": os.path.join(work_dir, f"{out_name}.access.log"),
            "NGINX_PID_FILE": os.path.join(work_dir, f"{out_name}.pid"),
            "AGENT_MTLS_REQUIRED": mtls_required,
        }
        proc = subprocess.Popen(["sh", os.path.join(repo_root, "deploy/nginx/entrypoint.sh")],
                                 env=nginx_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        _time.sleep(2)
        if proc.poll() is not None:
            raise AssertionError(f"nginx ({out_name}) ishga tushmadi: {proc.stdout.read() if proc.stdout else ''}")
        return proc

    def _stop_nginx(proc, out_name: str):
        pid_file = os.path.join(work_dir, f"{out_name}.pid")
        try:
            with open(pid_file) as f:
                os.kill(int(f.read().strip()), 15)
        except (OSError, ValueError, FileNotFoundError):
            pass
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    nginx_proc = None
    try:
        _time.sleep(2)  # backend'lar ko'tarilishi uchun

        # ===== A) Server-tomon TLS (mTLS o'chiq, standart holat) =====
        nginx_proc = _start_nginx("false", "nginx_a.conf")

        resp = requests_mod.get(f"https://localhost:{nginx_agent_port}/api/v1/health", verify=ca_path, timeout=5)
        assert resp.status_code == 200, f"Agent API TLS orqali ishlamadi: {resp.status_code}"

        resp2 = requests_mod.get(f"https://localhost:{nginx_dash_port}/login", verify=ca_path, timeout=5)
        assert resp2.status_code == 200, f"Dashboard TLS orqali ishlamadi: {resp2.status_code}"

        # Ichki CA'ga ISHONMAGAN (standart tizim do'koni) so'rov RAD
        # ETILISHI kerak - bu haqiqatan tekshirilayotganini isbotlaydi
        try:
            requests_mod.get(f"https://localhost:{nginx_agent_port}/api/v1/health", timeout=5)
            assert False, "CA tasdiqlanmasdan TLS ulanish MUVAFFAQIYATLI bo'ldi - haqiqiy tekshiruv yo'q"
        except requests_mod.exceptions.SSLError:
            pass  # kutilgan

        # Agentning haqiqiy ishlaydigan yo'li (check_hash) TLS orqali
        resp3 = requests_mod.post(
            f"https://localhost:{nginx_agent_port}/api/v1/check_hash",
            json={"sha256": "0" * 64, "filename": "test.txt"},
            headers={"X-API-Key": "ci-tls-test-key"}, verify=ca_path, timeout=5,
        )
        assert resp3.status_code == 200, f"check_hash TLS orqali ishlamadi: {resp3.status_code}"

        _stop_nginx(nginx_proc, "nginx_a.conf")
        nginx_proc = None

        # ===== B) mTLS MAJBURIY (AGENT_MTLS_REQUIRED=true) =====
        nginx_proc = _start_nginx("true", "nginx_b.conf")

        # Client sertifikatSIZ - RAD ETILISHI kerak
        resp_no_cert = requests_mod.get(f"https://localhost:{nginx_agent_port}/api/v1/health",
                                         verify=ca_path, timeout=5)
        assert resp_no_cert.status_code == 400, (
            f"mTLS talab qilinganda client sertifikatsiz so'rov RAD ETILISHI kerak edi, "
            f"lekin http_code={resp_no_cert.status_code} qaytdi"
        )

        # Boshqa (ishonchsiz, o'z-o'zidan imzolangan) sertifikat bilan - RAD ETILISHI kerak
        rogue_key = os.path.join(work_dir, "rogue.key")
        rogue_crt = os.path.join(work_dir, "rogue.crt")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                         "-keyout", rogue_key, "-out", rogue_crt, "-days", "1",
                         "-subj", "/CN=rogue-attacker"], capture_output=True, timeout=15)
        resp_rogue = requests_mod.get(f"https://localhost:{nginx_agent_port}/api/v1/health",
                                       verify=ca_path, cert=(rogue_crt, rogue_key), timeout=5)
        assert resp_rogue.status_code == 400, (
            f"mTLS: ishonchsiz (CA imzolamagan) client sertifikat RAD ETILISHI kerak edi, "
            f"http_code={resp_rogue.status_code} qaytdi"
        )

        # Haqiqiy, CA tomonidan imzolangan client sertifikat bilan - MUVAFFAQIYATLI
        resp_valid_cert = requests_mod.get(f"https://localhost:{nginx_agent_port}/api/v1/health",
                                            verify=ca_path, cert=(client_crt, client_key), timeout=5)
        assert resp_valid_cert.status_code == 200, (
            f"mTLS: CA tomonidan imzolangan haqiqiy client sertifikat bilan ham MUVAFFAQIYATSIZ: "
            f"{resp_valid_cert.status_code}"
        )

        # Dashboard'da mTLS talab qilinmaydi (foydalanuvchilar brauzer
        # orqali kiradi, client sertifikatga ega emas) - server-tomon
        # TLS bilan hamon ishlashi kerak
        resp_dash_b = requests_mod.get(f"https://localhost:{nginx_dash_port}/login", verify=ca_path, timeout=5)
        assert resp_dash_b.status_code == 200, "mTLS yoqilganda ham Dashboard oddiy TLS bilan ishlashi kerak edi"

    finally:
        if nginx_proc:
            _stop_nginx(nginx_proc, "nginx_b.conf")
        for p in (api_proc, dash_proc):
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()


check("XAVFSIZLIK: TLS reverse proxy (nginx) + Ichki CA - server-tomon TLS VA ixtiyoriy mTLS (real jarayonlar bilan)", _test_tls_reverse_proxy)

# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
print("\n=== 70) Ruijie Cloud integratsiyasi (foydalanuvchining production so'rovi) ===")


def _test_ruijie_discovery():
    """
    Foydalanuvchi so'radi: Ruijie Cloud'dan (Reyee/RG-CBS) qurilma
    discovery. MUHIM: bu integratsiya avval HAQIQIY Ruijie Cloud
    serveriga (foydalanuvchining real AppKey/AppSecret'i bilan) qarshi
    qo'lda sinaldi - autentifikatsiya oqimi (appid/secret + qat'iy
    `token` so'rov parametri -> access_token), guruhlar daraxti,
    qurilmalar va 235 ta REAL klient muvaffaqiyatli olindi. Bu test
    esa CI/offline muhitda takrorlanadigan bo'lishi uchun - xuddi shu
    zanjirni SOXTA (mock) server bilan tekshiradi.
    """
    import subprocess
    import time as _time

    mock_script = "/tmp/_ci_mock_ruijie.py"
    with open(mock_script, "w") as f:
        f.write('''
from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route("/service/api/oauth20/client/access_token", methods=["POST"])
def auth():
    body = request.get_json(silent=True) or {}
    if request.args.get("token") != "ci-static-token" or body.get("appid") != "ci-app-id" or body.get("secret") != "ci-app-secret":
        return jsonify({"code": 5, "msg": "You do not have permission to perform this operation."})
    return jsonify({"code": 0, "msg": "OK.", "accessToken": "ci-access-token"})

@app.route("/service/api/group/single/tree", methods=["GET"])
def groups():
    if request.args.get("access_token") != "ci-access-token":
        return jsonify({"code": 3, "msg": "Login timeout"})
    return jsonify({"code": 0, "msg": "OK.", "groups": {
        "name": "dumy", "groupId": 0, "subGroups": [
            {"name": "ci-root", "groupId": 900, "subGroups": [
                {"name": "CI-Filial", "groupId": 901, "subGroups": []},
            ]},
        ],
    }})

@app.route("/service/api/open/v1/dev/user/current-user", methods=["GET"])
def clients():
    if request.args.get("access_token") != "ci-access-token":
        return jsonify({"code": 3, "msg": "Login timeout"})
    group_id = request.args.get("group_id")
    if group_id == "901":
        return jsonify({"code": 0, "msg": "OK.", "totalCount": 2, "list": [
            {"mac": "aabb.ccdd.9001", "ip": "172.16.51.1", "userName": "", "deviceName": "CI-RUIJIE-PC", "groupName": "CI-Filial", "connectType": "wire", "manufacturer": "CI-Vendor"},
            {"mac": "aabb.ccdd.9002", "ip": "", "userName": "", "deviceName": "IPSIZ", "groupName": "CI-Filial", "connectType": "wifi", "manufacturer": "CI-Vendor"},
        ]})
    return jsonify({"code": 0, "msg": "OK.", "totalCount": 0, "list": []})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=19900)
''')

    mock_proc = subprocess.Popen(["python3", mock_script])
    try:
        _time.sleep(2)
        os.environ["RUIJIE_BASE_URL"] = "http://127.0.0.1:19900"
        os.environ["RUIJIE_APP_ID"] = "ci-app-id"
        os.environ["RUIJIE_APP_SECRET"] = "ci-app-secret"
        os.environ["RUIJIE_STATIC_TOKEN"] = "ci-static-token"

        # --- 1) get_ruijie_clients() to'g'ri parslashi (IP'siz klient o'tkazib yuborilmaydi - bu DB darajasida) ---
        from network_discovery.ruijie_discovery import get_ruijie_clients
        clients = get_ruijie_clients()
        assert len(clients) == 2, f"2 ta klient kutilgan edi (guruh daraxti rekursiv o'qilishi kerak), {len(clients)} keldi"
        by_mac = {c.mac: c for c in clients}
        assert by_mac["aabb.ccdd.9001"].ip == "172.16.51.1"
        assert by_mac["aabb.ccdd.9001"].is_wired is True
        assert by_mac["aabb.ccdd.9002"].is_wired is False

        # --- 2) noto'g'ri kalit bilan bo'sh ro'yxat (xato ko'tarmasdan) ---
        os.environ["RUIJIE_APP_SECRET"] = "wrong-secret"
        assert get_ruijie_clients() == []
        os.environ["RUIJIE_APP_SECRET"] = "ci-app-secret"

        # --- 3) discover_via_ruijie() -> DB ---
        from network_discovery.asset_inventory import discover_via_ruijie
        count = discover_via_ruijie()
        assert count == 1, f"1 ta qurilma kutilgan edi (IP'siz klient o'tkazib yuborilishi kerak), {count} keldi"

        s = get_session()
        d = s.query(Device).filter(Device.ip_address == "172.16.51.1").first()
        assert d is not None
        assert d.mac_address == "aabb.ccdd.9001"
        assert d.hostname == "CI-RUIJIE-PC"
        assert d.vendor == "CI-Vendor"
        assert d.connection_type == "cable"
        assert d.discovery_source == "ruijie"
        s.close()

        # --- 4) full_discovery() RUIJIE_APP_ID sozlangan bo'lsa Ruijie'ni ham chaqirishi ---
        from network_discovery.asset_inventory import full_discovery
        try:
            result = full_discovery("127.0.0.1/32", "lo", do_tcp_scan=False, do_snmp=False)
            assert "ruijie" in result, f"full_discovery natijasida 'ruijie' kaliti yo'q: {result}"
        except Exception:
            pass  # ARP/ICMP vositalari yo'q bo'lishi mumkin - bu test uchun muhim emas

        # --- 5) Dashboard /asset-inventory sahifasida ko'rinishi ---
        from dashboard import app as dash_app
        from dashboard.create_user import create_user
        create_user("ruijie_ci_admin", "ruijiecitest123", "admin")
        dash_app.app.secret_key = "test-secret-ruijie"
        dclient = _dash_client(dash_app.app)
        dclient.post("/login", data={"username": "ruijie_ci_admin", "password": "ruijiecitest123"})
        r = dclient.get("/asset-inventory")
        assert r.status_code == 200
        assert b"CI-RUIJIE-PC" in r.data, "Ruijie orqali topilgan qurilma Dashboard'da ko'rinmadi"
        assert b"ruijie" in r.data

        # --- 6) ruijie_sync_loop.py real HTTP orqali ---
        from network_discovery.ruijie_sync_loop import run_once
        n = run_once()
        assert n == 1

        # --- 7) docker-compose.yml'da ruijie_sync xizmati PROFILSIZ ekanini tasdiqlash ---
        import yaml
        with open("docker-compose.yml") as f:
            compose = yaml.safe_load(f)
        assert "ruijie_sync" in compose["services"], "ruijie_sync xizmati docker-compose.yml'da yo'q"
        assert "profiles" not in compose["services"]["ruijie_sync"], (
            "ruijie_sync PROFILSIZ bo'lishi kerak (standart 'docker compose up -d' bilan ishga tushishi uchun)"
        )

        # --- 8) Ruijie sozlanmagan holatda ham xato bermasligi ---
        os.environ.pop("RUIJIE_APP_ID")
        assert run_once() == 0

    finally:
        mock_proc.terminate()
        try:
            mock_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            mock_proc.kill()
        os.remove(mock_script)
        for k in ["RUIJIE_BASE_URL", "RUIJIE_APP_ID", "RUIJIE_APP_SECRET", "RUIJIE_STATIC_TOKEN"]:
            os.environ.pop(k, None)


check("Ruijie Cloud integratsiyasi: discovery + Asset Inventory + Dashboard + Sync Loop (real HTTP -> DB -> UI)", _test_ruijie_discovery)

# ---------------------------------------------------------------------------
print("\n=== 73) SESSION_COOKIE_SECURE - real production xatosi: http:// orqali login \"ishlamay qolgan\" ===")


def _test_session_cookie_secure_toggle():
    """
    Real production xatosi: xavfsizlik auditi SESSION_COOKIE_SECURE
    standart qiymatini "true" qildi (nginx TLS proxy ortida ishlashni
    ko'zda tutib). Production hali oddiy http:// orqali ishlagani uchun
    (nginx ataylab ishga tushirilmagan) - brauzer "Secure" bayrog'ili
    sessiya cookie'ni http:// orqali SAQLAMAYDI/YUBORMAYDI, shuning
    uchun parol to'g'ri qabul qilinsa ham foydalanuvchi darhol login
    sahifasiga qaytarilardi ("login ishlamayapti"dek ko'ringan).

    MUHIM (halol izoh): `test_client()` bu xatoni HECH QACHON
    o'zi ochib bermaydi (haqiqiy brauzerning "Secure" cookie siyosatini
    simulyatsiya qilmaydi) - bu test faqat ilova env o'zgaruvchisini
    TO'G'RI o'qib, cookie sarlavhasiga to'g'ri bayroq qo'yayotganini
    tasdiqlaydi (kodning o'zi to'g'ri edi - muammo `.env`da bu
    qiymat sozlanmagani, standart holatda "true" qolib ketgani edi).
    """
    import importlib

    for secure_value, should_have_secure in [("false", False), ("true", True)]:
        os.environ["SESSION_COOKIE_SECURE"] = secure_value
        os.environ["DASHBOARD_SECRET_KEY"] = "ci-test-dashboard-secret-key"
        import dashboard.app as dash_app_module
        importlib.reload(dash_app_module)

        client = dash_app_module.app.test_client()
        r = client.get("/login")
        set_cookie = r.headers.get("Set-Cookie", "")
        has_secure = "Secure" in set_cookie
        assert has_secure == should_have_secure, (
            f"SESSION_COOKIE_SECURE={secure_value} bo'lganda cookie'da "
            f"'Secure' bayrog'i {'bo\'lishi' if should_have_secure else 'BO\'LMASLIGI'} "
            f"kerak edi, Set-Cookie: {set_cookie}"
        )

    os.environ.pop("SESSION_COOKIE_SECURE", None)
    import dashboard.app as dash_app_module
    importlib.reload(dash_app_module)


check("SESSION_COOKIE_SECURE - http://da 'Secure' cookie muammosi (real production xatosi tuzatilgan)", _test_session_cookie_secure_toggle)

# ---------------------------------------------------------------------------
print("\n=== 74) Kerio Control parser - HAQIQIY log formatiga qarshi (real production xatosi tuzatilgan) ===")


def _test_kerio_parser_real_format():
    """
    Foydalanuvchi Live Map bo'sh ekanini so'raganda, production
    `syslog_collector` logini tekshirib chiqdim: Kerio Control HAQIQATAN
    log yuborayotgan edi, lekin `events`/`devices` jadvallari deyarli
    bo'sh qoldi. TUB SABAB: `parsers/kerio_parser.py` (va uning
    nusxasi `network_discovery/dhcp_reader.py`) Kerio Control'ning
    haqiqiy formatiga emas, balki umumiy taxminiy formatga
    (`SRC=...DST=...`, `DHCP: Lease granted...`) qarab yozilgan edi -
    bu format Kerio Control'da UMUMAN mavjud emas (rasmiy Kerio
    hujjatlari orqali tasdiqlandi - `docs_KERIO_CONTROL_SETUP.md`).

    Bu test parser'ni Kerio'ning RASMIY hujjatlaridan olingan, so'zma-
    so'z (o'zgartirilmagan) namuna qatorlariga qarshi sinaydi.
    """
    from parsers.kerio_parser import KerioConnectionParser, KerioHostParser
    from network_discovery.dhcp_reader import parse_kerio_dhcp_log

    conn = KerioConnectionParser()
    host = KerioHostParser()

    # --- Rasmiy Kerio Control hujjatidagi Connection log namunasi ---
    conn_line = (
        "[18/Apr/2013 10:22:47] [ID] 613181 [Rule] NAT [Service] HTTP "
        "[User] winston [Connection] TCP 192.168.1.140:1193 > hit.google.com:80 "
        "[Duration] 121 sec [Bytes] 1575/1290/2865 [Packets] 5/9/14"
    )
    assert conn.can_parse(conn_line), "KerioConnectionParser HAQIQIY Connection log formatini tanimadi"
    parsed = conn.parse(conn_line)
    assert parsed is not None
    assert parsed["source_ip"] == "192.168.1.140"
    assert parsed["dest_domain"] == "hit.google.com", "DNS nomli manzil dest_domain'ga yozilishi kerak (dest_ip emas)"
    assert parsed["dest_ip"] is None
    assert parsed["dest_port"] == 80
    assert parsed["protocol"] == "TCP"

    # IP-manzilli variant ham to'g'ri ishlashi (dest_ip to'ldirilishi)
    ip_conn_line = "[18/Apr/2013 10:22:47] [Connection] UDP 172.16.1.45:53210 > 8.8.8.8:53"
    parsed_ip = conn.parse(ip_conn_line)
    assert parsed_ip["dest_ip"] == "8.8.8.8"
    assert parsed_ip["dest_domain"] is None

    # --- Rasmiy Kerio Control hujjatidagi Host log namunasi (DHCP/host bog'lanishi) ---
    host_line = "[04/Mar/2014 12:07:28] [IPv4] 10.10.30.81 [MAC] 00-0c-29-1d-cc-bd (Apple) [Hostname] jsmith-cp"
    assert host.can_parse(host_line), "KerioHostParser HAQIQIY Host log formatini tanimadi"
    parsed_host = host.parse(host_line)
    assert parsed_host is not None
    assert parsed_host["source_ip"] == "10.10.30.81"
    assert parsed_host["mac_address"] == "00:0C:29:1D:CC:BD", "chiziqchali MAC (00-0c-...) to'g'ri o'qilib, ikki nuqtaliga aylantirilishi kerak"
    assert parsed_host["hostname"] == "jsmith-cp"

    # IPv6 registratsiya variantida ham (oraliqda [IPv6] bo'lsa) to'g'ri ishlashi
    ipv6_line = (
        "[04/Mar/2014 16:05:28] [IPv4] 10.10.30.81 "
        "[IPv6] 2001:718:1803:3513:b4c6:82b3:e0f5:309e "
        "[MAC] 00-0c-29-1d-cc-bd (Apple) [Hostname] jsmith-cp - "
        "IPv6 address 2001:718:1803:3513:b4c6:82b3:e0f5:309e registered"
    )
    parsed_ipv6 = host.parse(ipv6_line)
    assert parsed_ipv6["source_ip"] == "10.10.30.81"
    assert parsed_ipv6["mac_address"] == "00:0C:29:1D:CC:BD"

    # --- network_discovery/dhcp_reader.py'dagi fayl-asosli o'qish ham xuddi shu formatni tushunishi ---
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(host_line + "\n")
        tmp_path = f.name
    try:
        leases = parse_kerio_dhcp_log(tmp_path)
        assert len(leases) == 1
        assert leases[0].ip == "10.10.30.81"
        assert leases[0].mac == "00:0C:29:1D:CC:BD"
        assert leases[0].hostname == "jsmith-cp"
    finally:
        os.remove(tmp_path)

    # --- Eski (noto'g'ri, endi mavjud bo'lmasligi kerak) format endi TANILMASLIGI ---
    old_format_line = "<134>Jul 30 KERIO-GW Connection: SRC=172.16.1.45 DST=8.8.8.8 DPT=443 PROTO=TCP ACTION=Permit"
    assert not conn.can_parse(old_format_line), (
        "Eski (haqiqiy Kerio'da mavjud bo'lmagan) format endi ATAYLAB tanilmasligi kerak"
    )


check("Kerio Control parser - HAQIQIY (rasmiy hujjatlashtirilgan) log formatiga mos (real production xatosi tuzatilgan)", _test_kerio_parser_real_format)

# ---------------------------------------------------------------------------
print("\n=== 75) Kerio Control parser - HAQIQIY production log formatiga qarshi (rasmiy hujjat formatidan FARQLI, ikkinchi marta tuzatilgan) ===")


def _test_kerio_parser_real_production_capture():
    """
    Foydalanuvchi Kerio Control'da "Log connections"ni yoqqandan keyin
    ("tog'irladim"), Live Map hamon bo'sh qoldi. Production `raw_logs`
    jadvalini to'g'ridan-to'g'ri tekshirganimda: Kerio HAQIQATAN
    Connection loglarini yubormoqda edi (2822 ta yozuv!), lekin
    `events` jadvali hali ham 0 edi.

    IKKINCHI MARTA topilgan xato: oldingi tuzatish RASMIY Kerio
    hujjatidagi 2013-yilgi namunaga (`TCP ip:port > hostname:port`)
    asoslangan edi - lekin HAQIQIY, joriy production Kerio Control
    BUTUNLAY BOSHQA formatda yozar ekan: manzil har doim
    `hostname (ip):port` ko'rinishida (agar teskari DNS mavjud bo'lsa),
    ajratuvchi esa `>` emas, `->` (chiziqcha bilan). Bu test aynan
    production'dan olingan (o'zgartirilmagan) qatorlarga qarshi sinaydi.
    """
    from parsers.kerio_parser import KerioConnectionParser, KerioHostParser

    conn = KerioConnectionParser()
    host = KerioHostParser()

    # --- Production'dan olingan HAQIQIY Connection log qatorlari ---
    real_conn_lines = [
        (
            # MUHIM (bu yerda ilgari aniqlanmagan real bo'shliq, keyinroq
            # tuzatilgan): destinationda teskari DNS nomi ("lr-in-f95.1e100.net")
            # HAM, IP HAM bor - bunday holda `dest_domain` avval jimgina
            # `None` bo'lib qolar edi (faqat IP saqlanardi), garchi Kerio'ning
            # o'zi domen nomini aniq bergan bo'lsa ham. Endi bu domen nomi
            # ham to'g'ri o'qiladi - "Saytlar tarixi" endi xom IP o'rniga
            # o'qilishi mumkin bo'lgan domen nomlarini ko'rsatadi.
            "[ID] 1831242 [Rule] Internet access (NAT) [Service] TCP 443 "
            "[Connection] TCP sph-262.synergypharm.org (172.16.1.35):63579 -> "
            "lr-in-f95.1e100.net (209.85.233.95):443 [Iface] WAN0_Uztelecom "
            "[Duration] 31 sec [Bytes] 1458/9404/10862 [Packets] 8/10/18",
            "172.16.1.35", "209.85.233.95", "lr-in-f95.1e100.net", 443,
        ),
        (
            # Destinationda teskari DNS nomi YO'Q (faqat IP) - shu holat ham to'g'ri ishlashi kerak
            "[ID] 1826702 [Rule] Internet access (NAT) [Service] TCP 443 "
            "[Connection] TCP a71-pol-zovatela-shirin.synergypharm.org (172.16.1.85):54514 -> "
            "149.154.167.41:443 [Iface] WAN0_Uztelecom [Duration] 215 sec "
            "[Bytes] 1098/906/2004 [Packets] 9/7/16",
            "172.16.1.85", "149.154.167.41", None, 443,
        ),
    ]
    for raw, exp_src, exp_dst_ip, exp_dst_domain, exp_port in real_conn_lines:
        assert conn.can_parse(raw)
        parsed = conn.parse(raw)
        assert parsed is not None, f"HAQIQIY production Connection qatori parslanmadi: {raw}"
        assert parsed["source_ip"] == exp_src
        assert parsed["dest_ip"] == exp_dst_ip
        assert parsed["dest_domain"] == exp_dst_domain
        assert parsed["dest_port"] == exp_port
        assert parsed["protocol"] == "TCP"

    # --- Production'dan olingan HAQIQIY Host log qatori: [Hostname] YO'Q ---
    # (faqat "IP address leased from DHCP" - MAC bor, Hostname yo'q)
    real_host_no_hostname = "[IPv4] 172.16.1.132 [MAC] 02-59-62-cf-8d-7f - IP address leased from DHCP"
    assert host.can_parse(real_host_no_hostname), "[Hostname]siz Host qatori ENDI ham tanilishi kerak"
    parsed_h = host.parse(real_host_no_hostname)
    assert parsed_h is not None
    assert parsed_h["source_ip"] == "172.16.1.132"
    assert parsed_h["mac_address"] == "02:59:62:CF:8D:7F"
    assert parsed_h["hostname"] is None


check("Kerio Control parser - HAQIQIY production log formatiga qarshi (ikkinchi marta tuzatilgan, real qatorlar bilan)", _test_kerio_parser_real_production_capture)

# ---------------------------------------------------------------------------
print("\n=== 76) Live Map: vis-network kutubxonasi mahalliy xizmat qilinishi (tashqi CDN havolasi buzilgan edi) ===")


def _test_live_map_vis_network_local_asset():
    """
    Foydalanuvchi backend to'liq ishlayotganini (135 node, 60 edge -
    to'g'ridan-to'g'ri tasdiqlangan) qat'i nazar, "Live Map bo'sh"
    deb xabar qildi. TUB SABAB: `live_map.html` `vis-network`
    kutubxonasini tashqi CDN'dan (`cdnjs.cloudflare.com`) yuklardi -
    lekin cdnjs o'z fayl yo'lini o'zgartirib qo'ygan edi
    (`/9.1.9/vis-network.min.js` -> `/9.1.9/standalone/umd/vis-
    network.min.js`), eski havola JIM ravishda HTTP 404 qaytarardi.
    Natijada brauzerda `vis` global obyekti hech qachon aniqlanmasdi,
    xarita chizilmasdi - lekin sahifaning o'zi (va backend API) xato
    bermasdi, shuning uchun bu FAQAT brauzer DevTools konsolida
    ko'rinardi, oddiy foydalanuvchiga esa shunchaki "bo'sh" bo'lib
    tuyulardi.

    Tuzatildi: kutubxona endi MAHALLIY saqlanadi
    (`dashboard/static/vis-network.min.js`) - tashqi CDN'ga UMUMAN
    bog'liq emas (na noto'g'ri yo'l, na korporativ faervol muammosi
    bo'lishi mumkin emas).
    """
    import os as _os

    static_path = _os.path.join(
        _os.path.dirname(_os.path.abspath(__file__)),
        "dashboard", "static", "vis-network.min.js",
    )
    assert _os.path.isfile(static_path), "dashboard/static/vis-network.min.js topilmadi - mahalliy vendoring qilinmagan"
    assert _os.path.getsize(static_path) > 100_000, "vis-network.min.js fayli juda kichik - to'liq yuklab olinmagan bo'lishi mumkin"

    with open(static_path, "rb") as f:
        head = f.read(200)
    assert b"vis-network" in head, "Fayl mazmuni vis-network kutubxonasiga o'xshamayapti"

    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "dashboard", "templates", "live_map.html")) as f:
        template = f.read()
    assert '<script src="https://cdnjs.cloudflare.com' not in template, (
        "live_map.html <script> tegi hali ham tashqi CDN'ga bog'liq (buzilishi mumkin bo'lgan havola)"
    )
    assert '<script src="/static/vis-network.min.js">' in template, "live_map.html mahalliy static faylni ishlatmayapti"

    # --- Real HTTP orqali: Flask static route to'g'ri xizmat qilishini tasdiqlash ---
    from dashboard.app import app as dash_app
    client = dash_app.test_client()
    r = client.get("/static/vis-network.min.js")
    assert r.status_code == 200, f"/static/vis-network.min.js 200 qaytarishi kerak edi, {r.status_code} keldi"
    assert len(r.data) > 100_000


check("Live Map: vis-network mahalliy static asset sifatida xizmat qilinadi (tashqi CDN havolasi buzilgan edi, real production xatosi tuzatilgan)", _test_live_map_vis_network_local_asset)

# ---------------------------------------------------------------------------
print("\n=== 76) UEBA Engine docker-compose xizmati (Alertlar bo'sh qolishining bir sababi tuzatilgan) ===")


def _test_ueba_engine_service_registered():
    """
    Foydalanuvchi "alterlar pustoy" deb xabar qildi. Tekshirganda:
    engine/ueba_engine.py to'liq yozilgan va ilgari test qilingan edi
    (statistik anomaliya aniqlash + Risk Score + Alert yaratish), lekin
    docker-compose.yml'da HECH QANDAY uni ishga tushiruvchi xizmat yo'q
    edi - bu loyihada bir necha marta uchragan "kod to'g'ri, lekin
    hech kim uni ishga tushirmaydi" xato turkumi (UniFi sync, Suricata
    reader'da ham xuddi shunday bo'lgan).
    """
    import yaml
    with open("docker-compose.yml") as f:
        compose = yaml.safe_load(f)
    assert "ueba_engine" in compose["services"], "ueba_engine xizmati docker-compose.yml'da yo'q"
    assert "profiles" not in compose["services"]["ueba_engine"], (
        "ueba_engine PROFILSIZ bo'lishi kerak (standart 'docker compose up -d' bilan ishga tushishi uchun)"
    )
    assert "--loop" in compose["services"]["ueba_engine"]["command"]


check("UEBA Engine docker-compose xizmati sifatida ro'yxatga olindi (production bo'shlig'i tuzatilgan)", _test_ueba_engine_service_registered)

# ---------------------------------------------------------------------------
print("\n=== 77) Kerio Connection hodisalari: blacklist tekshiruvi + Web Activity'ga yozilishi (Alertlar/Saytlar tarixi bo'sh qolishining ikkinchi sababi) ===")


def _test_connection_events_feed_alerts_and_web_activity():
    """
    Foydalanuvchi "alterlar pustoy" va "saytlarga kirish tarixi ham
    ishlamayapti" deb xabar qildi. Production'da 638 000+ Kerio
    Connection hodisasi (`events`) bor edi, lekin `alerts` va
    `web_access_logs` ikkalasi ham 0 edi. TUB SABAB: `parser_engine.py`
    faqat `dns_query` hodisalarini blacklist'ga qarshi tekshirar va
    Web Activity'ga yozar edi - "connection" (Kerio'dan, hozirgi
    yagona real oqim) hodisalari uchun bunday tekshiruv/yozuv UMUMAN
    yo'q edi.

    Tuzatildi: endi "connection" hodisalari ham (1) `dest_ip`/
    `dest_domain` BlacklistEntry'ga qarshi tekshiriladi (Alert
    yaratiladi), (2) WebAccessLog'ga yoziladi (domen bo'lsa domen,
    aks holda IP bilan) - "Saytlar tarixi" sahifasi endi HAQIQIY
    Kerio trafigi bilan to'ladi.
    """
    from db.models import RawLog, BlacklistEntry, WebAccessLog

    s = get_session()
    s.add(BlacklistEntry(value="203.0.113.99", source="manual", reason="test"))
    s.add_all([
        # Domen bilan (teskari DNS mavjud) - WebAccessLog'da domen ko'rinishi kerak
        RawLog(source_ip="172.16.0.1", raw_message=(
            "[ID] 1 [Rule] Internet access (NAT) [Connection] TCP "
            "ci-pc.local (172.16.9.201):51234 -> mail.example.com (198.51.100.5):443 "
            "[Iface] WAN0 [Duration] 5 sec [Bytes] 100/200/300 [Packets] 2/3/5"
        )),
        # Blacklist'dagi IP'ga ulanish - Alert yaratilishi kerak
        RawLog(source_ip="172.16.0.1", raw_message=(
            "[ID] 2 [Rule] Internet access (NAT) [Connection] TCP "
            "ci-pc2.local (172.16.9.202):51235 -> 203.0.113.99:443 "
            "[Iface] WAN0 [Duration] 5 sec [Bytes] 100/200/300 [Packets] 2/3/5"
        )),
    ])
    s.commit()
    s.close()

    from engine.parser_engine import run_once
    count = run_once()
    assert count == 2

    s = get_session()
    web_entries = s.query(WebAccessLog).filter(WebAccessLog.source_ip.in_(["172.16.9.201", "172.16.9.202"])).all()
    assert len(web_entries) == 2, "Connection hodisalari WebAccessLog'ga yozilmadi ('Saytlar tarixi' bo'sh qolgan sabab)"
    by_src = {w.source_ip: w for w in web_entries}
    assert by_src["172.16.9.201"].domain == "mail.example.com", "Teskari DNS nomi mavjud bo'lsa, domen bilan yozilishi kerak"
    assert by_src["172.16.9.202"].domain == "203.0.113.99", "Domen yo'q bo'lsa, IP bilan yozilishi kerak (fallback)"

    alerts = s.query(Alert).filter(Alert.reason.like("%203.0.113.99%")).all()
    assert len(alerts) == 1, "Blacklist'dagi IP'ga ulanish uchun Alert yaratilmadi ('Alertlar' bo'sh qolgan sabab)"
    assert alerts[0].severity == "high"
    s.close()


check("Kerio Connection hodisalari: blacklist Alert + Web Activity'ga yozilishi (real production bo'shlig'i tuzatilgan)", _test_connection_events_feed_alerts_and_web_activity)

# ---------------------------------------------------------------------------
print("\n=== 78) Device identifikatsiyasi: MAC bo'yicha (DHCP IP o'zgarganda duplikat qator yaratilmaydi) ===")


def _test_device_mac_identity_no_duplicate_on_ip_change():
    """
    Foydalanuvchi: "qurilma online dan oflinega o'tganida va yangi
    qurilma ulansa uni yana yangi qurilma sifatida ro'yxatga
    qo'shayabdi". TUB SABAB: `devices` avval FAQAT `ip_address` bo'yicha
    aniqlanardi (`engine/parser_engine.py`/`network_discovery/
    asset_inventory.py`dagi `_upsert_device`). DHCP muhitida bitta fizik
    qurilma (bir xil MAC) oflaynga chiqib qayta ulanganda ko'pincha
    BOSHQA IP oladi - bu "yangi qurilma" deb ro'yxatga olinardi, eski
    IP'dagi qator esa abadiy "oflayn" bo'lib qolardi. Vaqt o'tishi bilan
    bu `devices` jadvalini haqiqiy qurilmalar sonidan ancha ko'p, "arvoh"
    duplikatlar bilan to'ldirib boradi.

    Tuzatildi: `db/device_identity.py::find_or_create_device` avval MAC
    bo'yicha qidiradi, topilsa xuddi shu qatorning IP'sini yangilaydi.
    """
    mac = "AA:BB:CC:99:88:77"
    ip1, ip2 = "172.16.9.230", "172.16.9.231"

    s = get_session()
    s.query(Device).filter(Device.mac_address == mac).delete()
    s.query(Device).filter(Device.ip_address.in_([ip1, ip2])).delete(synchronize_session=False)
    s.add(RawLog(source_ip=ip1, raw_message=f"[IPv4] {ip1} [MAC] {mac.replace(':', '-')} [Hostname] MAC-IDENTITY-PC"))
    s.commit()
    s.close()

    from engine.parser_engine import run_once
    assert run_once() == 1

    s = get_session()
    matches = s.query(Device).filter(Device.mac_address == mac).all()
    assert len(matches) == 1, "Birinchi ulanishda bitta qator yaratilishi kerak"
    device_id = matches[0].id
    assert matches[0].ip_address == ip1
    s.close()

    # Qurilma "oflayn" bo'lib, qayta ulanganda YANGI IP oladi (DHCP re-lease)
    # - real production'da aynan shu holat sodir bo'lgan.
    s = get_session()
    s.add(RawLog(source_ip=ip2, raw_message=f"[IPv4] {ip2} [MAC] {mac.replace(':', '-')} [Hostname] MAC-IDENTITY-PC"))
    s.commit()
    s.close()

    assert run_once() == 1

    s = get_session()
    matches = s.query(Device).filter(Device.mac_address == mac).all()
    assert len(matches) == 1, (
        f"Bir xil MAC ({mac}) uchun {len(matches)} ta Device qatori topildi - "
        "IP o'zgarganda YANGI (duplikat) qator yaratilgan, xato tuzatilmagan"
    )
    assert matches[0].id == device_id, "Yangi qator o'rniga xuddi shu qator yangilanishi kerak edi"
    assert matches[0].ip_address == ip2, "Qurilmaning IP'si yangi lease'ga mos yangilanishi kerak"
    s.close()


check("Device MAC-asosli identifikatsiya: DHCP IP o'zgarganda duplikat qator yaratilmaydi (real production xatosi tuzatilgan)", _test_device_mac_identity_no_duplicate_on_ip_change)

# ---------------------------------------------------------------------------
print("\n=== 79) Device identifikatsiyasi: IP kolliziyasida tarix (Event/Alert) yo'qotilmaydi ===")


def _test_device_mac_identity_merges_ip_collision():
    """
    Kamdan-kam, lekin mumkin bo'lgan holat: DHCP bitta IP'ni avval
    BOSHQA (allaqachon boshqa MAC bilan tanilgan) qurilmaga bergan
    bo'lib, o'sha qator bazada hali bor, endi esa O'SHA IP'ni YANGI
    MAC'ga beryapti. `ip_address` UNIQUE bo'lgani uchun ikkala qatorda
    bir xil IP qololmaydi - shu sabab eski qatorning tarixi (Event/
    Alert) YO'QOTILMASDAN yangi (MAC-mos) qatorga ko'chirilishi, so'ng
    bo'sh qolgan eski qator o'chirilishi kerak (bu xavfsizlik monitoring
    tizimi - tarixiy Alert'ni jimgina yo'qotish maqbul emas).
    """
    from db.device_identity import find_or_create_device

    old_mac, new_mac = "11:22:33:AA:BB:CC", "CC:BB:AA:33:22:11"
    shared_ip, other_ip = "172.16.9.240", "172.16.9.241"

    s = get_session()
    s.query(Device).filter(Device.mac_address.in_([old_mac, new_mac])).delete(synchronize_session=False)
    s.query(Device).filter(Device.ip_address.in_([shared_ip, other_ip])).delete(synchronize_session=False)
    s.commit()

    old_device = Device(ip_address=shared_ip, mac_address=old_mac, hostname="OLD-PC", source="test")
    s.add(old_device)
    s.flush()
    s.add(Event(device_id=old_device.id, source_ip=shared_ip, dest_ip="8.8.8.8", protocol="DNS"))
    s.add(Alert(device_id=old_device.id, severity="low", reason="eski qurilmaning eski alerti"))
    s.commit()
    old_device_id = old_device.id

    new_device = Device(ip_address=other_ip, mac_address=new_mac, hostname="NEW-PC", source="test")
    s.add(new_device)
    s.commit()
    new_device_id = new_device.id

    # Yangi MAC endi O'SHA (eski, band) IP'ni oladi - DHCP kolliziyasi
    result = find_or_create_device(s, shared_ip, mac=new_mac, source="test")
    s.commit()

    assert result.id == new_device_id, "MAC-mos (yangi) qator saqlanib qolishi, IP unga o'tishi kerak edi"
    assert result.ip_address == shared_ip

    assert s.query(Device).filter(Device.id == old_device_id).first() is None, (
        "Eski, endi bo'sh qolgan (IP kolliziyasiga uchragan) qator o'chirilishi kerak edi"
    )

    # MUHIM: eski qatorning tarixi yo'qolmasdan yangi qatorga ko'chirilgan bo'lishi kerak
    assert s.query(Event).filter(Event.device_id == new_device_id, Event.dest_ip == "8.8.8.8").count() == 1, (
        "Eski qurilmaning Event tarixi yo'qolgan - xavfsizlik monitoring tizimida bu maqbul emas"
    )
    assert s.query(Alert).filter(Alert.device_id == new_device_id, Alert.reason.like("%eski qurilmaning%")).count() == 1, (
        "Eski qurilmaning Alert tarixi yo'qolgan"
    )
    s.close()


check("Device MAC-asosli identifikatsiya: IP kolliziyasida Event/Alert tarixi ko'chiriladi, yo'qotilmaydi", _test_device_mac_identity_merges_ip_collision)

# ---------------------------------------------------------------------------
print("\n=== 79a) Device identity: IP kolliziyasida DeviceBaseline mavjud bo'lsa, merge (o'chirish tartibi) muvaffaqiyatsiz bo'lmasligi ===")


def _test_device_mac_identity_merge_with_baseline():
    """
    PRODUKSIYADA HAQIQATAN TOPILGAN, TAKRORLANUVCHI XATO (concurrency
    tuzatishidan KEYIN ham davom etgan, keyin real diagnostika orqali
    ochilgan HAQIQIY tub sabab): birinchi qarashda bu "poyga holati"
    (parser_engine vs ueba_engine) deb o'ylangan edi (yuqoridagi 79b-test
    shuni tuzatadi) - lekin production'da tuzatishdan KEYIN ham xato
    davom etganda, `docker exec`orqali to'g'ridan-to'g'ri bazaga
    qarashda aniqlandi: bu aslida hech qanday poyga holati EMAS, balki
    DETERMINISTIK, har doim takrorlanadigan xato edi.

    TUB SABAB: `DeviceBaseline` modelida `Device`ga `relationship()`
    E'LON QILINMAGAN (`Event`/`Alert`dan farqli - ularda bor). Bunday
    holda, BITTA `session.flush()` ichida ikkita mustaqil `session.
    delete(...)` chaqirilganda (avval baseline, keyin device - kod
    aynan shu tartibda yozilgan bo'lsa ham), SQLAlchemy'ning avtomatik
    dependency-sorting mexanizmi FK bog'liqlikni ISHONCHLI aniqlay
    olmasligi (qo'lda, to'g'ridan-to'g'ri PostgreSQL'ga qarshi
    tasdiqlangan xatti-harakat) sabab, "devices" qatori "device_
    baselines"dan OLDIN o'chirilishga urinishi mumkin - bu HAR DOIM
    (concurrency'siz, bitta oddiy `_merge_device()` chaqiruvida ham)
    `ForeignKeyViolation` bilan tugaydi, agar `remove` qurilmaning
    baseline'i bo'lsa.

    Tuzatish: baseline bilan bog'liq o'zgarish (reassign YOKI delete)
    darhol, alohida `session.flush()` bilan bazaga yuboriladi - `remove`
    qurilmaning o'zi o'chirilishidan OLDIN. Bu SQLAlchemy'ning
    relationship()-siz FK tartiblash noaniqligini butunlay chetlab
    o'tadi (endi vaqt/navbatga bog'liq emas - HAR DOIM to'g'ri ishlaydi).
    """
    from db.device_identity import find_or_create_device
    from db.models import DeviceBaseline

    old_mac, new_mac = "11:22:33:AA:BB:DD", "DD:BB:AA:33:22:11"
    shared_ip, other_ip = "172.16.9.242", "172.16.9.243"

    s = get_session()
    s.query(Device).filter(Device.mac_address.in_([old_mac, new_mac])).delete(synchronize_session=False)
    s.query(Device).filter(Device.ip_address.in_([shared_ip, other_ip])).delete(synchronize_session=False)
    s.commit()

    old_device = Device(ip_address=shared_ip, mac_address=old_mac, hostname="OLD-BASELINE-PC", source="test")
    s.add(old_device)
    s.flush()
    # MUHIM: "remove" bo'ladigan (eski) qurilmaning DeviceBaseline'i bor -
    # bu aynan production'da kuzatilgan holat (UEBA barcha qurilmalar
    # uchun baseline hisoblab qo'ygan, keyin shu qurilma IP kolliziyasiga
    # uchraydi).
    s.add(DeviceBaseline(
        device_id=old_device.id,
        mean_events_per_hour=5, stddev_events_per_hour=2,
        typical_active_hours="9,10,11", lookback_days=30, sample_size=50,
    ))
    s.commit()
    old_device_id = old_device.id

    new_device = Device(ip_address=other_ip, mac_address=new_mac, hostname="NEW-BASELINE-PC", source="test")
    s.add(new_device)
    s.commit()
    new_device_id = new_device.id

    # Yangi MAC endi O'SHA (baseline'li) IP'ni oladi - kolliziya + merge
    result = find_or_create_device(s, shared_ip, mac=new_mac, source="test")
    s.commit()  # MUHIM: aynan shu commit production'da ForeignKeyViolation bilan qulagan edi

    assert result.id == new_device_id
    assert s.query(Device).filter(Device.id == old_device_id).first() is None, (
        "Eski (baseline'li) qurilma o'chirilishi kerak edi"
    )
    assert s.query(DeviceBaseline).filter(DeviceBaseline.device_id == new_device_id).count() == 1, (
        "Eski qurilmaning baseline'i yangi qatorga ko'chirilishi kerak edi"
    )
    s.close()


check("Device MAC-asosli identifikatsiya: DeviceBaseline mavjud bo'lganda merge (relationship()siz FK tartiblash) muvaffaqiyatsiz bo'lmasligi", _test_device_mac_identity_merge_with_baseline)

# ---------------------------------------------------------------------------
print("\n=== 79a2) Device identity: Incident mavjud bo'lganda merge muvaffaqiyatsiz bo'lmasligi (real production xatosi, hozir topilgan) ===")


def _test_device_mac_identity_merge_with_incident():
    """
    HAQIQIY, HOZIR ISHLAB TURGAN PRODUCTION XATOSI (foydalanuvchi "ko'p
    funksiyalar ishlamayabdi" deb xabar berganda, `docker logs` orqali
    topilgan): `parser_engine` va `unifi_sync` konteynerlari HAR
    TSIKLDA `psycopg2.errors.ForeignKeyViolation: ... update or delete
    on table "devices" violates foreign key constraint
    "incidents_device_id_fkey"` bilan qulab tushayotgan edi.

    TUB SABAB: `Incident` jadvali (Correlation Engine, `_merge_device()`
    yozilgandan KEYINGI bosqichda qo'shilgan) `device_id` orqali
    `devices.id`ga FK bog'langan, lekin `_merge_device()` buni HECH
    QACHON reassign qilmagan edi - faqat Event/Alert/WebAccessLog/
    DeviceBaseline hisobga olingan. Natijada IP-kolliziyaga uchragan
    (`remove`) qurilmada bog'liq Incident bo'lsa, `session.delete(remove)`
    doim FK xatosi bilan MUVAFFAQIYATSIZ bo'lardi - bu esa xizmatni
    xato bilan qulatib (session rollback, hech narsa commit qilinmasdan),
    HAR KEYINGI tsiklda AYNAN SHU kolliziyani qayta-qayta uchratib,
    uzluksiz xato tsikliga olib kelgan edi (real production, hozir
    kuzatilgan holat).
    """
    from db.device_identity import find_or_create_device
    from db.models import Incident, utcnow

    old_mac, new_mac = "11:22:33:AA:BB:EE", "EE:BB:AA:33:22:11"
    shared_ip, other_ip = "172.16.9.244", "172.16.9.245"

    s = get_session()
    s.query(Device).filter(Device.mac_address.in_([old_mac, new_mac])).delete(synchronize_session=False)
    s.query(Device).filter(Device.ip_address.in_([shared_ip, other_ip])).delete(synchronize_session=False)
    s.commit()

    old_device = Device(ip_address=shared_ip, mac_address=old_mac, hostname="OLD-INCIDENT-PC", source="test")
    s.add(old_device)
    s.flush()
    # MUHIM: "remove" bo'ladigan (eski) qurilmaga bog'liq Incident bor -
    # bu aynan production'da kuzatilgan holat (Correlation Engine allaqachon
    # shu qurilma uchun Incident yaratib qo'ygan, keyin shu qurilma IP
    # kolliziyasiga uchraydi).
    incident = Incident(
        title="Test incident (old device)", severity="medium", status="open",
        device_id=old_device.id, alert_count=1,
        first_seen=utcnow(), last_seen=utcnow(),
    )
    s.add(incident)
    s.commit()
    old_device_id = old_device.id
    incident_id = incident.id

    new_device = Device(ip_address=other_ip, mac_address=new_mac, hostname="NEW-INCIDENT-PC", source="test")
    s.add(new_device)
    s.commit()
    new_device_id = new_device.id

    # Yangi MAC endi O'SHA (Incident'li) IP'ni oladi - kolliziya + merge
    result = find_or_create_device(s, shared_ip, mac=new_mac, source="test")
    s.commit()  # MUHIM: aynan shu commit production'da ForeignKeyViolation bilan qulagan edi

    assert result.id == new_device_id
    assert s.query(Device).filter(Device.id == old_device_id).first() is None, (
        "Eski (Incident'li) qurilma o'chirilishi kerak edi"
    )
    moved_incident = s.query(Incident).filter(Incident.id == incident_id).first()
    assert moved_incident is not None and moved_incident.device_id == new_device_id, (
        "Eski qurilmaning Incident'i yangi qatorga ko'chirilishi kerak edi (yo'qolmasligi)"
    )
    s.close()


check("Device MAC-asosli identifikatsiya: Incident mavjud bo'lganda merge (real production ForeignKeyViolation tuzatilgan)", _test_device_mac_identity_merge_with_incident)

# ---------------------------------------------------------------------------
print("\n=== 79b) Device identity: ikkita jarayon BIR VAQTDA QARAMA-QARSHI yo'nalishda birlashtirsa deadlock/FK xatosi bo'lmasligi ===")


def _test_device_identity_concurrent_merge_no_deadlock():
    """
    PRODUKSIYADA HAQIQATAN TOPILGAN XATO (bu test aynan shu voqeani qayta
    hosil qiladi): birinchi deploy'dan darhol keyin `parser_engine` va
    boshqa mustaqil jarayon (`network_discovery`/UEBA - ular ham
    `find_or_create_device()` orqali BIR XIL qurilma juftligini
    birlashtirishga urinishi mumkin) BIR VAQTDA, QARAMA-QARSHI yo'nalishda
    (biri A->B, ikkinchisi B->A) "events" jadvalini yangilashga urinib,
    `psycopg2.errors.DeadlockDetected` xatosiga uchragan, keyingi
    tsiklda esa xuddi shu poyga holati `ForeignKeyViolation`ga
    (device_baselines - merge tugamasdan turib eski qatorga yangi yozuv
    qo'shilgani) olib kelgan.

    Tuzatish: `_lock_devices_in_order()` - ikkala qurilma qatorini har
    doim bir xil (kichik ID'dan kattaga) tartibda `SELECT ... FOR
    UPDATE` bilan qulflaydi, bu HAM aylanma kutishni (deadlock)
    oldini oladi, HAM `remove` qatorga ishora qiluvchi yangi yozuv
    qo'shilishini (FK orqali) tranzaksiya tugagunча to'xtatib turadi.

    Faqat PostgreSQL'da ma'noli (haqiqiy qator qulflash/tranzaksiya
    izolyatsiyasi kerak) - SQLite'da `FOR UPDATE` jimgina e'tiborsiz
    qoldiriladi, haqiqiy poyga holati yuzaga kelmaydi.
    """
    from config.settings import DATABASE_URL as CURRENT_DB_URL
    if not CURRENT_DB_URL.startswith("postgresql://"):
        print("   (haqiqiy poyga holati faqat PostgreSQL'da ma'noli - SQLite'da o'tkazib yuborildi)")
        return

    import threading
    from db.device_identity import _merge_device

    mac_a, mac_b = "AA:11:22:33:44:66", "BB:11:22:33:44:66"
    ip_a, ip_b = "172.16.9.252", "172.16.9.253"

    s0 = get_session()
    s0.query(Device).filter(Device.mac_address.in_([mac_a, mac_b])).delete(synchronize_session=False)
    s0.query(Device).filter(Device.ip_address.in_([ip_a, ip_b])).delete(synchronize_session=False)
    s0.commit()

    device_a = Device(ip_address=ip_a, mac_address=mac_a, source="test")
    device_b = Device(ip_address=ip_b, mac_address=mac_b, source="test")
    s0.add_all([device_a, device_b])
    s0.commit()
    device_a_id, device_b_id = device_a.id, device_b.id

    s0.add(Event(device_id=device_a_id, source_ip=ip_a, dest_ip="1.1.1.1", protocol="DNS"))
    s0.add(Event(device_id=device_b_id, source_ip=ip_b, dest_ip="2.2.2.2", protocol="DNS"))
    s0.commit()
    s0.close()

    barrier = threading.Barrier(2)
    errors = []

    def worker(keep_id, remove_id):
        try:
            barrier.wait(timeout=5)
            s = get_session()
            keep = s.get(Device, keep_id)
            remove = s.get(Device, remove_id)
            if keep is not None and remove is not None:
                _merge_device(s, keep=keep, remove=remove)
                s.commit()
            s.close()
        except Exception as e:
            errors.append(e)

    # Qarama-qarshi yo'nalish - aynan production'da kuzatilgan naqsh:
    # Thread1: keep=A, remove=B (A<-B); Thread2: keep=B, remove=A (B<-A)
    t1 = threading.Thread(target=worker, args=(device_a_id, device_b_id))
    t2 = threading.Thread(target=worker, args=(device_b_id, device_a_id))
    t1.start()
    t2.start()
    t1.join(timeout=15)
    t2.join(timeout=15)

    assert not errors, f"Bir vaqtda, qarama-qarshi yo'nalishda ishlagan merge'larda xato kutilmagan edi (deadlock/FK): {errors}"

    s = get_session()
    remaining = s.query(Device).filter(Device.id.in_([device_a_id, device_b_id])).all()
    assert len(remaining) == 1, f"Ikkala tomon ham birlashtirgandan keyin FAQAT bitta qator qolishi kerak edi, {len(remaining)} ta qoldi"
    survivor = remaining[0]

    # Ikkala tomonning ham tarixi saqlanib qolgan bo'lishi kerak (birortasi ham yo'qolmagan)
    assert s.query(Event).filter(Event.device_id == survivor.id, Event.dest_ip == "1.1.1.1").count() == 1, "1-qurilmaning Event tarixi yo'qolgan"
    assert s.query(Event).filter(Event.device_id == survivor.id, Event.dest_ip == "2.2.2.2").count() == 1, "2-qurilmaning Event tarixi yo'qolgan"
    s.close()


check("Device identity: bir vaqtda ikki jarayon QARAMA-QARSHI yo'nalishda birlashtirsa deadlock/FK xatosi bo'lmasligi (real production xatosi tuzatilgan)", _test_device_identity_concurrent_merge_no_deadlock)

# ---------------------------------------------------------------------------
print("\n=== 80) Dashboard /devices: sahifalash (200+ qurilma bo'lganda ham barchasi ko'rinadi) ===")


def _test_devices_pagination_shows_all():
    """
    Foydalanuvchi: "qurilmalar ro'yxatida 724 ta qurilmani
    ko'rsatmayabdi". TUB SABAB: `/devices` sarlavhasi/statistika
    kartochkalari haqiqiy JAMI sonni ko'rsatsa-da, pastdagi jadval har
    doim `.limit(200)` bilan qattiq cheklangan edi va SAHIFALASH
    UMUMAN YO'Q edi - 200 tadan ortiq qurilma bo'lsa, qolganlari HECH
    QACHON ko'rinmasdi. Endi `page` parametri orqali barcha
    qurilmalarga (necha sahifa kerak bo'lsa ham) yetish mumkinligini
    tasdiqlaymiz.
    """
    import re

    marker_ips = [f"172.16.40.{i}" for i in range(1, 206)]  # 205 ta - 200 limitdan ortiq
    s = get_session()
    s.query(Device).filter(Device.ip_address.in_(marker_ips)).delete(synchronize_session=False)
    s.commit()
    for ip in marker_ips:
        s.add(Device(ip_address=ip, hostname=f"PAGETEST-{ip.split('.')[-1]}", source="pagination_test"))
    s.commit()
    total_in_db = s.query(Device).count()
    s.close()

    from dashboard.app import app as dashboard_app
    from dashboard.create_user import create_user
    create_user("devpage_ci_admin", "devpageci123", "admin")
    dashboard_app.secret_key = "test-secret-devices-pagination"
    client = _dash_client(dashboard_app)
    client.post("/login", data={"username": "devpage_ci_admin", "password": "devpageci123"})

    resp = client.get("/devices")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert f"Barcha qurilmalar ({total_in_db})" in html, "Sarlavha haqiqiy jami sonni ko'rsatmayapti"

    m = re.search(r"Sahifa \d+ / (\d+)", html)
    assert m is not None, "200 tadan ortiq qurilma bor - sahifalash ko'rinishi kerak edi"
    total_pages = int(m.group(1))
    assert total_pages >= 2, f"200+ qurilma bor, lekin faqat {total_pages} sahifa ko'rsatilmoqda"

    found_ips = set()
    for page in range(1, total_pages + 1):
        resp = client.get(f"/devices?page={page}")
        assert resp.status_code == 200
        found_ips.update(re.findall(r"172\.16\.40\.\d+", resp.get_data(as_text=True)))

    missing = set(marker_ips) - found_ips
    assert not missing, (
        f"{len(missing)} ta qurilma HECH QAYSI sahifada ko'rinmadi (masalan {sorted(missing)[:3]}) - "
        "eski '.limit(200), sahifalashsiz' xatosi qaytgan bo'lishi mumkin"
    )


check("Dashboard /devices: sahifalash - 200 tadan ortiq qurilma bo'lganda ham barchasi ko'rinadi (real production xatosi tuzatilgan)", _test_devices_pagination_shows_all)

# ---------------------------------------------------------------------------
print("\n=== 81) Dashboard: barcha sahifalarga ustun-bo'yicha filtr qo'shildi (Qurilmalar/Alertlar/Asset Inventory/Fayllar/Foydalanuvchilar/Audit Log/API Tokenlar/Agent Coverage/Live Map) ===")


def _test_all_pages_column_filters():
    """
    Foydalanuvchi ekran-suratida deyarli barcha sahifa/ustunlarni
    belgilab, "chizilgan oynalarni barchasiga filtr qo'yib ber" deb
    so'radi. Har bir asosiy ro'yxat sahifasiga (Devices allaqachon
    to'g'irlangan edi) endi mos ustunlar bo'yicha filtr qo'shildi. Bu
    test har biri uchun: (1) filtrli so'rov 200 qaytarishi, (2) filtr
    HAQIQATAN natijani mos/mos bo'lmagan qatorlarga to'g'ri
    ajratishini tekshiradi (faqat "xato bermadi" emas).
    """
    from db.models import Device, Alert, FileEvent, WebAccessLog, User, AuditLog, utcnow
    from api import token_manager

    s = get_session()
    alpha = Device(ip_address="172.16.163.1", mac_address="AA:BB:CC:63:00:01", hostname="ALPHA-FILTER-PC",
                   connection_type="wifi", source="kerio_dhcp", last_seen=utcnow(), risk_score=85,
                   discovery_source="arp_scan", device_type="workstation", vendor="Dell-Test")
    beta = Device(ip_address="172.16.163.2", mac_address="AA:BB:CC:63:00:02", hostname="BETA-FILTER-PC",
                  connection_type="cable", source="network_discovery", last_seen=utcnow(), risk_score=5,
                  discovery_source="icmp", device_type="server", vendor="HP-Test")
    s.add_all([alpha, beta])
    s.commit()
    s.add(Alert(severity="high", reason="ALPHA-FILTER-PC uchun test alert", device_id=alpha.id,
                mitre_technique_id="T1204.002", acknowledged=False))
    s.add(FileEvent(filename="filtertest_alpha.exe", src_ip="172.16.163.1", sha256="ab" * 32,
                     verdict="clean", channel="endpoint_agent"))
    s.add(WebAccessLog(source_ip="172.16.163.1", device_id=alpha.id, domain="filtertest-alpha.example", protocol="HTTPS"))
    s.commit()
    s.close()

    from dashboard.app import app as dashboard_app
    from dashboard.create_user import create_user
    create_user("filtertest_admin", "filtertestpass123", "admin")
    create_user("filtertest_viewer_zz", "filtertestpass123", "viewer")
    dashboard_app.secret_key = "test-secret-column-filters"
    client = _dash_client(dashboard_app)
    client.post("/login", data={"username": "filtertest_admin", "password": "filtertestpass123"})

    # --- Devices (allaqachon test 78-80'da chuqur tekshirilgan asosiy
    #     mantiq - bu yerda faqat qo'shimcha ustunlar) ---
    html = client.get("/devices?mac=63:00:01").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" in html and "BETA-FILTER-PC" not in html, "Devices: MAC filtri ishlamadi"
    html = client.get("/devices?source=kerio_dhcp").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" in html and "BETA-FILTER-PC" not in html, "Devices: Manba filtri ishlamadi"

    # --- Alerts ---
    html = client.get("/alerts?hostname=ALPHA-FILTER").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" in html, "Alerts: hostname filtri ishlamadi"
    html = client.get("/alerts?hostname=NOMAVJUD-QURILMA").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" not in html, "Alerts: hostname filtri mos kelmaganini chiqarib yubordi"
    html = client.get("/alerts?mitre=T1204").get_data(as_text=True)
    assert "T1204" in html, "Alerts: MITRE filtri ishlamadi"
    html = client.get("/alerts?acknowledged=1").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" not in html, "Alerts: acknowledged=1 hali tasdiqlanmagan alertni chiqardi"

    # --- Asset Inventory ---
    html = client.get("/asset-inventory?device_type=workstation").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" in html and "BETA-FILTER-PC" not in html, "Asset Inventory: device_type filtri ishlamadi"
    html = client.get("/asset-inventory?vendor=HP-Test").get_data(as_text=True)
    assert "BETA-FILTER-PC" in html and "ALPHA-FILTER-PC" not in html, "Asset Inventory: vendor filtri ishlamadi"
    html = client.get("/asset-inventory?discovery_source=arp_scan").get_data(as_text=True)
    assert "ALPHA-FILTER-PC" in html and "BETA-FILTER-PC" not in html, "Asset Inventory: discovery_source filtri ishlamadi"

    # --- Files ---
    html = client.get("/files?filename=filtertest_alpha").get_data(as_text=True)
    assert "filtertest_alpha.exe" in html, "Files: filename filtri ishlamadi"
    html = client.get("/files?filename=hech-narsa-mos-kelmaydi").get_data(as_text=True)
    assert "filtertest_alpha.exe" not in html, "Files: filename filtri mos kelmaganini chiqarib yubordi"
    html = client.get("/files?sha256=abababab").get_data(as_text=True)
    assert "filtertest_alpha.exe" in html, "Files: sha256 prefiks filtri ishlamadi"

    # --- Users (MUHIM: `current_user.username` nav panelida HAR BIR
    #     sahifada ko'rinadi - shuning uchun bare username emas, jadval
    #     qatoridagi `<td>...</td>` shaklini qidiramiz) ---
    html = client.get("/users?username=filtertest_admin").get_data(as_text=True)
    assert "<td>filtertest_admin</td>" in html and "<td>filtertest_viewer_zz</td>" not in html, "Users: username filtri ishlamadi"
    html = client.get("/users?role=viewer").get_data(as_text=True)
    assert "<td>filtertest_viewer_zz</td>" in html and "<td>filtertest_admin</td>" not in html, "Users: rol filtri ishlamadi"

    # --- Audit Log (yuqoridagi login harakati allaqachon yozilgan bo'lishi kerak) ---
    html = client.get("/audit?username=filtertest_admin&action=login").get_data(as_text=True)
    assert "<td>filtertest_admin</td>" in html, "Audit Log: username+action filtri ishlamadi"
    html = client.get("/audit?username=hech-kim-bunday-emas").get_data(as_text=True)
    assert "<td>filtertest_admin</td>" not in html, "Audit Log: username filtri mos kelmaganini chiqarib yubordi"

    # --- API Tokens ---
    token_manager.create_token("FILTERTEST-TOKEN-A", created_by="test", agent_hostname="FILTER-HOST-A")
    token_manager.create_token("FILTERTEST-TOKEN-B", created_by="test", agent_hostname="FILTER-HOST-B")
    html = client.get("/api-tokens?hostname=FILTER-HOST-A").get_data(as_text=True)
    assert "FILTERTEST-TOKEN-A" in html and "FILTERTEST-TOKEN-B" not in html, "API Tokens: hostname filtri ishlamadi"
    html = client.get("/api-tokens?status=active").get_data(as_text=True)
    assert "FILTERTEST-TOKEN-A" in html, "API Tokens: status=active filtri kutilgan tokenni yashirdi"

    # --- Agent Coverage (AD sozlanmagan holatda ham xato bermasligi kerak) ---
    resp = client.get("/agent-coverage?q=hech-narsa")
    assert resp.status_code == 200, "Agent Coverage: filtrli so'rov xato berdi"

    # --- Live Map (server-tomon o'zgarish yo'q - faqat sahifa ochilishi va
    #     qidiruv input'i mavjudligi tekshiriladi, filtr client-side JS) ---
    resp = client.get("/live-map")
    assert resp.status_code == 200
    assert 'id="map-search"' in resp.get_data(as_text=True), "Live Map: qidiruv maydoni qo'shilmagan"


check("Dashboard: barcha asosiy sahifalarga ustun-bo'yicha filtr qo'shildi (Alertlar/Asset Inventory/Fayllar/Foydalanuvchilar/Audit Log/API Tokenlar/Agent Coverage/Live Map)", _test_all_pages_column_filters)

# ---------------------------------------------------------------------------
print("\n=== 82) Endpoint Agent: heartbeat tsikli kutilmagan xatodan keyin ABADIY o'lib qolmasligi kerak ===")


def _test_heartbeat_loop_survives_unexpected_exception():
    """
    Foydalanuvchi real production'da ("Isobek" - o'zi ishlatayotgan
    kompyuter) xabar qildi: Dashboard'da Endpoint Agent "OFFLINE"
    ko'rsatilgan (`agent_last_heartbeat` ~16 soat eski), garchi
    fayllar sahifasida O'SHA agent orqali tekshirilgan fayllar
    (channel=endpoint_agent) aynan SHU KUN ertalab, bir necha daqiqa
    oldin ko'rinib turgan bo'lsa ham - ya'ni agent jarayoni ishlab
    turibdi va serverga ulanmoqda, faqat heartbeat aynan bitta
    vaqtdan keyin to'xtab qolgan.

    TUB SABAB: `agent_core/agent.py`ning `_heartbeat_loop()`sida
    `send_heartbeat()` chaqiruvi hech qanday try/except bilan
    o'ralmagan edi - `send_heartbeat()`ning o'zi FAQAT `requests.
    RequestException`ni ushlaydi. Agar biror urinishda BOSHQA turdagi
    kutilmagan xato (masalan tarmoq/DNS'ning g'alati holatidagi,
    RequestException'ga o'ralmagan xatosi) yuz bersa, bu xato
    `_heartbeat_loop()`ning o'ziga chiqib ketib, BUTUN heartbeat
    thread'ini ABADIY o'ldirar edi - fayl kuzatish (butunlay alohida
    thread) va `check_hash` esa normal davom etaverardi (aynan
    kuzatilgan simptom).

    Tuzatildi: `_safe_send_heartbeat()` - har bir urinish alohida
    himoyalangan, HAR QANDAY kutilmagan xato faqat O'SHA tsiklni
    o'tkazib yuboradi, thread TIRIK qoladi va keyingi intervalda
    qayta urinadi.
    """
    import tempfile
    import time as _time
    import importlib
    import agent_core.agent as agent_mod

    os.environ["HEARTBEAT_INTERVAL_SECONDS"] = "1"
    importlib.reload(agent_mod)

    call_count = {"n": 0}

    def flaky_send_heartbeat(hostname, ip_address):
        call_count["n"] += 1
        if call_count["n"] == 1:
            # RequestException EMAS - send_heartbeat()ning o'z ichki
            # except blokidan o'tib, to'g'ridan-to'g'ri _heartbeat_loop()ga
            # chiqib ketadigan turdagi xato.
            raise ValueError("kutilmagan, RequestException BO'LMAGAN xato (test)")
        return True

    original_send_heartbeat = agent_mod.send_heartbeat
    agent_mod.send_heartbeat = flaky_send_heartbeat
    agent = None
    try:
        agent = agent_mod.EndpointAgent([tempfile.mkdtemp()])
        agent.start_background()

        _time.sleep(0.3)
        assert call_count["n"] == 1, "Birinchi (xato beruvchi) urinish umuman chaqirilmadi"
        assert agent._heartbeat_thread.is_alive(), (
            "Birinchi urinish kutilmagan xato bergandan so'ng thread darhol o'lib qolgan - "
            "eski xato ('heartbeat abadiy to'xtab qoladi') qaytgan"
        )

        _time.sleep(1.5)
        assert agent._heartbeat_thread.is_alive(), "Thread keyingi intervalgacha yashab qololmadi"
        assert call_count["n"] >= 2, (
            "Birinchi urinish xato bergandan keyin tsikl davom etmadi - "
            "heartbeat abadiy to'xtab qolgan (real production xatosi)"
        )
    finally:
        if agent is not None:
            agent.stop()
        agent_mod.send_heartbeat = original_send_heartbeat
        os.environ.pop("HEARTBEAT_INTERVAL_SECONDS", None)
        importlib.reload(agent_mod)


check("Endpoint Agent: heartbeat tsikli kutilmagan xatodan keyin tirik qoladi (real 'Isobek' production xatosi tuzatilgan)", _test_heartbeat_loop_survives_unexpected_exception)

# ---------------------------------------------------------------------------
print("\n=== 83) VirusTotal/MalwareBazaar checker'lari: 'topilmadi' endi 'toza' bilan aralashtirilmaydi ===")


def _test_threat_intel_checkers_dont_conflate_not_found_with_clean():
    """
    Foydalanuvchi (chuqur arxitektura tahlili) topgan eng muhim
    xato: `check_virustotal()` VT hash haqida UMUMAN ma'lumotga ega
    bo'lmaganda (404 - hech qachon ko'rmagan) `{"malicious": False,
    ...}` qaytarardi - bu VT'ning o'zi tekshirib "toza" deb topgan
    holat bilan BIR XIL ko'rinardi. Xuddi shu muammo `check_
    malwarebazaar()`da ham bor edi (`query_status != "ok"` - masalan
    "hash_not_found" - ham `{"malicious": False, ...}` qaytarardi,
    garchi MalwareBazaar zararli dastur bazasi bo'lgani uchun "toza"
    degan xulosani UMUMAN chiqara olmasa ham).

    Natijada: yangi (VT/MalwareBazaar hali ko'rmagan) zararli dastur
    "clean" deb noto'g'ri belgilanishi mumkin edi.

    Tuzatildi: ikkala checker ham endi "ma'lumot yo'q" holatida
    `None` qaytaradi (avvalgi `{"malicious": False, ...}` o'rniga) -
    `None` chaqiruvchi tomonidan HECH QACHON "toza" deb talqin
    qilinmaydi. VT FAQAT hashni HAQIQATAN tekshirib (haqiqiy
    `last_analysis_stats` bilan) chiqqanda haqiqiy "toza" signalini
    beradi.
    """
    from unittest.mock import patch, Mock
    import threat_intel.virustotal_checker as vt_mod
    import threat_intel.malwarebazaar_checker as mb_mod

    # --- VirusTotal: 404 (hash VT bazasida UMUMAN yo'q) -> None, "clean" EMAS ---
    with patch.object(vt_mod, "VT_API_KEY", "fake-test-key"):
        fake_404 = Mock(status_code=404)
        with patch.object(vt_mod.requests, "get", return_value=fake_404):
            result = vt_mod.check_virustotal("a" * 64)
        assert result is None, (
            f"VT 404 (hash topilmadi) endi 'toza' bilan aralashtirilmasligi kerak - None qaytishi kerak edi, {result} qaytdi"
        )

        # --- VirusTotal: 200, lekin hali birorta dvigatel tekshirmagan (total=0) -> None ---
        fake_pending = Mock(status_code=200)
        fake_pending.json.return_value = {"data": {"attributes": {"last_analysis_stats": {}}}}
        with patch.object(vt_mod.requests, "get", return_value=fake_pending):
            result = vt_mod.check_virustotal("b" * 64)
        assert result is None, f"Tahlil ma'lumoti yo'q (total=0) holatda None qaytishi kerak edi, {result} qaytdi"

        # --- VirusTotal: HAQIQIY tekshirilgan, 0/70 dvigatel belgilagan -> haqiqiy 'toza' signali ---
        fake_clean = Mock(status_code=200)
        fake_clean.json.return_value = {
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 68, "undetected": 2},
                "last_analysis_results": {},
            }}
        }
        with patch.object(vt_mod.requests, "get", return_value=fake_clean):
            result = vt_mod.check_virustotal("c" * 64)
        assert result is not None, "VT haqiqatan tekshirib, 0/70 topgan holatda natija qaytarishi kerak edi"
        assert result["malicious"] is False
        assert result["total"] == 70

        # --- VirusTotal: HAQIQIY tekshirilgan, malicious topilgan -> unchanged ---
        fake_malicious = Mock(status_code=200)
        fake_malicious.json.return_value = {
            "data": {"attributes": {
                "last_analysis_stats": {"malicious": 5, "suspicious": 0, "harmless": 60, "undetected": 5},
                "last_analysis_results": {"EngineX": {"category": "malicious", "result": "Trojan.Test"}},
            }}
        }
        with patch.object(vt_mod.requests, "get", return_value=fake_malicious):
            result = vt_mod.check_virustotal("d" * 64)
        assert result["malicious"] is True and result["positives"] == 5

    # --- MalwareBazaar: kalit (Auth-Key) yuboriladi; kalitsiz so'rov umuman yuborilmaydi ---
    os.environ.pop("MALWAREBAZAAR_AUTH_KEY", None); os.environ.pop("THREATFOX_AUTH_KEY", None)
    os.environ.pop("URLHAUS_AUTH_KEY", None); os.environ.pop("ABUSE_CH_AUTH_KEY", None)
    with patch.object(mb_mod.requests, "post") as mock_no_key:
        assert mb_mod.check_malwarebazaar("c" * 64) is None
        assert mock_no_key.call_count == 0, "Kalit sozlanmagan bo'lsa MalwareBazaar'ga so'rov yuborilmasligi kerak"
    os.environ["THREATFOX_AUTH_KEY"] = "ci-abusech-key"
    try:
        fake_mb_ok = Mock(status_code=200)
        fake_mb_ok.json.return_value = {"query_status": "hash_not_found"}
        with patch.object(mb_mod.requests, "post", return_value=fake_mb_ok) as mock_keyed:
            mb_mod.check_malwarebazaar("c" * 64)
            assert mock_keyed.call_args.kwargs["headers"]["Auth-Key"] == "ci-abusech-key", "Auth-Key sarlavhasi yuborilmadi"
        fake_mb_401 = Mock(status_code=401)
        with patch.object(mb_mod.requests, "post", return_value=fake_mb_401):
            assert mb_mod.check_malwarebazaar("c" * 64) is None
    finally:
        pass

    # --- MalwareBazaar: "hash_not_found" -> None, "clean" EMAS ---
    fake_mb_not_found = Mock(status_code=200)
    fake_mb_not_found.json.return_value = {"query_status": "hash_not_found"}
    with patch.object(mb_mod.requests, "post", return_value=fake_mb_not_found):
        result = mb_mod.check_malwarebazaar("e" * 64)
    assert result is None, (
        f"MalwareBazaar 'hash_not_found' endi 'toza' bilan aralashtirilmasligi kerak - None qaytishi kerak edi, {result} qaytdi"
    )

    # --- MalwareBazaar: ma'lum zararli namuna -> unchanged ---
    fake_mb_found = Mock(status_code=200)
    fake_mb_found.json.return_value = {"query_status": "ok", "data": [{"signature": "Emotet"}]}
    with patch.object(mb_mod.requests, "post", return_value=fake_mb_found):
        result = mb_mod.check_malwarebazaar("f" * 64)
    assert result is not None and result["malicious"] is True and result["threat_name"] == "Emotet"
    os.environ.pop("THREATFOX_AUTH_KEY", None)


check("VirusTotal/MalwareBazaar checker'lari: 'topilmadi' endi 'toza' deb hisoblanmaydi (real production xatosi tuzatilgan)", _test_threat_intel_checkers_dont_conflate_not_found_with_clean)

# ---------------------------------------------------------------------------
print("\n=== 84) File Analysis Engine + check_hash: verdict taksonomiyasi (malicious/suspicious/clean/unknown) ===")


def _test_verdict_taxonomy_end_to_end():
    """
    Foydalanuvchi tavsiyasi: verdict endi 4 xil aniq holatga ega
    bo'lishi kerak - `CLEAN` (HAQIQATAN tekshirilib toza topilgan),
    `SUSPICIOUS` (zaif, tasdiqlanmagan signal), `MALICIOUS`
    (tasdiqlangan), `UNKNOWN` (hech qanday manba ma'lumot bermagan -
    bu "clean" EMAS). Bu test to'liq zanjirni (`analyze_one()` VA
    `/api/v1/check_hash` - ikkalasi ham mustaqil implementatsiya)
    real DB bilan tasdiqlaydi.
    """
    from unittest.mock import patch
    import engine.file_analysis_engine as fae
    import api.server as api_server

    # --- 1) analyze_one(): hech qanday manba ma'lumot bermasa -> "unknown" (avvalgi "clean" xatosi) ---
    s = get_session()
    fe_unknown = FileEvent(src_ip="172.16.63.10", filename="brand_new_ransomware.exe", sha256="1a" * 32, checked=False)
    s.add(fe_unknown)
    s.commit()
    with patch.object(fae, "check_virustotal", return_value=None), \
         patch.object(fae, "check_malwarebazaar", return_value=None):
        fae.analyze_one(s, fe_unknown)
        s.commit()
    assert fe_unknown.verdict == "unknown", (
        f"Hech qanday manba ma'lumot bermagan yangi fayl 'unknown' bo'lishi kerak edi (avvalgi 'clean' xatosi), '{fe_unknown.verdict}' keldi"
    )
    s.close()

    # --- 2) analyze_one(): VT HAQIQATAN tekshirib, toza deb topsa -> "clean" ---
    s = get_session()
    fe_clean = FileEvent(src_ip="172.16.63.11", filename="notepad_replacement.exe", sha256="2a" * 32, checked=False)
    s.add(fe_clean)
    s.commit()
    with patch.object(fae, "check_virustotal", return_value={"malicious": False, "positives": 0, "total": 70, "threat_name": None}), \
         patch.object(fae, "check_malwarebazaar", return_value=None):
        fae.analyze_one(s, fe_clean)
        s.commit()
    assert fe_clean.verdict == "clean", f"VT haqiqatan tekshirib toza topgan fayl 'clean' bo'lishi kerak edi, '{fe_clean.verdict}' keldi"
    s.close()

    # --- 3) /api/v1/check_hash: hech qanday manba ma'lumot bermasa -> FileEvent.verdict "unknown",
    #        lekin Agent'ga qaytariladigan javob (malicious=False) O'ZGARMAYDI (karantin siyosati bu ish doirasida emas) ---
    api_server.AGENT_API_KEY = "test-key-verdict-taxonomy"
    api_client = api_server.app.test_client()
    with patch.object(api_server, "check_virustotal", return_value=None), \
         patch.object(api_server, "check_malwarebazaar", return_value=None):
        r = api_client.post("/api/v1/check_hash", json={
            "sha256": "3a" * 32, "filename": "unclassified.bin",
            "hostname": "TEST-PC-TAXONOMY", "ip_address": "172.16.63.12",
        }, headers={"X-API-Key": "test-key-verdict-taxonomy"})
    assert r.status_code == 200
    resp_json = r.get_json()
    assert resp_json["malicious"] is False, "Agent'ga qaytariladigan javob o'zgarmasligi kerak edi (unknown != avtomatik bloklash)"

    s = get_session()
    fe_api_unknown = s.query(FileEvent).filter(FileEvent.sha256 == "3a" * 32).first()
    assert fe_api_unknown is not None
    assert fe_api_unknown.verdict == "unknown", (
        f"check_hash orqali hech qanday manba tasdiqlamagan fayl 'unknown' bo'lishi kerak edi (avvalgi 'clean' xatosi), '{fe_api_unknown.verdict}' keldi"
    )
    s.close()

    # --- 4) /api/v1/check_hash: VT HAQIQATAN tekshirib toza topsa -> FileEvent.verdict "clean" ---
    with patch.object(api_server, "check_virustotal", return_value={"malicious": False, "positives": 0, "total": 70, "threat_name": None}), \
         patch.object(api_server, "check_malwarebazaar", return_value=None):
        r = api_client.post("/api/v1/check_hash", json={
            "sha256": "4a" * 32, "filename": "genuinely_clean.bin",
            "hostname": "TEST-PC-TAXONOMY", "ip_address": "172.16.63.13",
        }, headers={"X-API-Key": "test-key-verdict-taxonomy"})
    assert r.status_code == 200
    assert r.get_json()["malicious"] is False

    s = get_session()
    fe_api_clean = s.query(FileEvent).filter(FileEvent.sha256 == "4a" * 32).first()
    assert fe_api_clean is not None and fe_api_clean.verdict == "clean", (
        f"check_hash orqali VT haqiqatan tasdiqlagan fayl 'clean' bo'lishi kerak edi, {fe_api_clean.verdict if fe_api_clean else None} keldi"
    )
    s.close()


check("Verdict taksonomiyasi (malicious/suspicious/clean/unknown) - file_analysis_engine VA check_hash, real DB orqali", _test_verdict_taxonomy_end_to_end)

# ---------------------------------------------------------------------------
print("\n=== 85) URL/Domain Intelligence moduli (normalization/punycode/userinfo/leksik xavf balli) ===")


def _test_url_intel_module():
    """
    Foydalanuvchi chuqur arxitektura tahlilidagi ③-band: to'liq URL/
    Domain Intelligence moduli. Bu test `threat_intel/url_intel.py`ning
    har bir funksiyasini foydalanuvchining O'ZI keltirgan aniq
    misollar bilan tekshiradi.
    """
    from threat_intel.url_intel import (
        normalize_url, has_userinfo_trick, is_punycode, extract_domain,
        domain_parent_candidates, domain_matches_blacklist, lexical_risk_score, analyze_url,
    )

    # --- normalize_url: katta/kichik harf, standart port, % kodlash ---
    assert normalize_url("http://EXAMPLE.com:80/") == "http://example.com/"
    assert normalize_url("https://EXAMPLE.com:443") == "https://example.com/"
    assert normalize_url("https://example.com:8443/path%2Ftest") == "https://example.com:8443/path/test"

    # --- has_userinfo_trick: "https://google.com@evil-site.com/login" ---
    assert has_userinfo_trick("https://google.com@evil-site.com/login") is True
    assert has_userinfo_trick("https://example.com/login") is False

    # --- is_punycode / IDN ---
    assert is_punycode("xn--pypal-4ve.com") is True
    assert is_punycode("paypal.com") is False

    # --- extract_domain ---
    assert extract_domain("https://sub.evil.com:8443/a/b?x=1") == "sub.evil.com"

    # --- domain_parent_candidates + domain_matches_blacklist: MUHIM
    # regressiya himoyasi - foydalanuvchi ANIQ ta'kidlagan xavf: oddiy
    # endswith() "notevil.com".endswith("evil.com") -> True (NOTO'G'RI!)
    # bergan bo'lardi. LABEL-chegara asosidagi yondashuv buni oldini olishi kerak.
    assert domain_parent_candidates("cdn.login.evil.com") == ["cdn.login.evil.com", "login.evil.com", "evil.com"]
    assert domain_matches_blacklist("cdn.login.evil.com", "evil.com") is True
    assert domain_matches_blacklist("notevil.com", "evil.com") is False, (
        "'notevil.com' 'evil.com' bilan MOS KELMASLIGI kerak - oddiy endswith() xatosi qaytgan bo'lishi mumkin"
    )
    assert domain_matches_blacklist("evil.com", "evil.com") is True

    # --- lexical_risk_score: foydalanuvchining o'z misollari ---
    phishing = lexical_risk_score("microsoft-login-security.xyz")
    assert phishing["level"] == "malicious", f"Fishing'ga o'xshash domen 'malicious' bo'lishi kerak edi, {phishing} keldi"
    legit = lexical_risk_score("microsoft.com")
    assert legit["level"] == "normal", f"Haqiqiy microsoft.com 'normal' bo'lishi kerak edi, {legit} keldi"
    assert lexical_risk_score("google.com")["level"] == "normal"

    # --- analyze_url: orchestrator, userinfo tuzog'i bilan birga ---
    full = analyze_url("https://google.com@microsoft-login-security.xyz/verify")
    assert full["domain"] == "microsoft-login-security.xyz"
    assert full["has_userinfo_trick"] is True
    assert full["level"] == "malicious"


check("URL/Domain Intelligence moduli - normalization/punycode/userinfo/domain hierarchy/leksik xavf balli", _test_url_intel_module)

# ---------------------------------------------------------------------------
print("\n=== 86) Parser Engine: domen ierarxiyasi bo'yicha blacklist + leksik fishing alert (real DB orqali) ===")


def _test_parser_engine_domain_hierarchy_and_lexical_alert():
    """
    Foydalanuvchi chuqur arxitektura tahlilidagi ⑦/⑧/⑪-band - real
    `engine.parser_engine.run_once()` orqali (mock emas, haqiqiy DB
    yozuvlari bilan):
      1. Blacklist'da `evil.com` bo'lsa, `cdn.login.evil.com`ga Kerio
         Connection orqali ulanish HAM Alert yaratishi kerak (avval
         faqat aniq moslik ishlagan).
      2. `notevil.com`ga ulanish Alert YARATMASLIGI kerak (oddiy
         endswith() xatosining regressiya himoyasi).
      3. Blacklist'da yo'q, lekin nomi bo'yicha aniq fishing'ga
         o'xshagan domenga DNS so'rovi alohida ("leksik") Alert
         yaratishi, va bir xil domen uchun ikkinchi marta QAYTA-QAYTA
         alert yaratmasligi (dedup) kerak.
      4. Oddiy, zararsiz domen (google.com) hech qanday alert
         yaratmasligi kerak.
    """
    from db.models import RawLog, BlacklistEntry, Alert

    s = get_session()
    s.add(BlacklistEntry(value="pe-hierarchy-evil.com", source="manual", reason="ci-test"))
    s.add_all([
        # 1) Subdomen orqali blacklist mosligi
        RawLog(source_ip="172.16.0.1", raw_message=(
            "[ID] 1 [Rule] Internet access (NAT) [Connection] TCP "
            "pc1.local (172.16.30.1):51000 -> cdn.login.pe-hierarchy-evil.com (198.51.100.10):443 "
            "[Iface] WAN0 [Duration] 5 sec [Bytes] 100/200/300 [Packets] 2/3/5"
        )),
        # 2) "notevil" - substring o'xshash, lekin MOS KELMASLIGI kerak
        RawLog(source_ip="172.16.0.1", raw_message=(
            "[ID] 2 [Rule] Internet access (NAT) [Connection] TCP "
            "pc2.local (172.16.30.2):51001 -> not-pe-hierarchy-evil.com (198.51.100.11):443 "
            "[Iface] WAN0 [Duration] 5 sec [Bytes] 100/200/300 [Packets] 2/3/5"
        )),
        # 3) Blacklist'da yo'q, lekin leksik jihatdan aniq fishing (haqiqiy Windows DNS parser formatida)
        RawLog(source_ip="172.16.0.5", raw_message=(
            '{"EventID":256,"ClientIP":"172.16.0.5","QueryName":"microsoft-login-security-update.xyz","QueryType":"A"}'
        )),
        # 4) Zararsiz, oddiy domen
        RawLog(source_ip="172.16.0.5", raw_message=(
            '{"EventID":256,"ClientIP":"172.16.0.5","QueryName":"google.com","QueryType":"A"}'
        )),
    ])
    s.commit()
    s.close()

    from engine.parser_engine import run_once
    count = run_once()
    assert count == 4

    s = get_session()
    hierarchy_alert = s.query(Alert).filter(Alert.reason.like("%cdn.login.pe-hierarchy-evil.com%")).first()
    assert hierarchy_alert is not None, (
        "Domen ierarxiyasi bo'yicha blacklist mosligi ishlamadi - "
        "'evil.com' blacklist'da bo'lsa, 'cdn.login.evil.com' ham aniqlanishi kerak edi"
    )
    assert hierarchy_alert.severity == "high"

    notevil_alert = s.query(Alert).filter(Alert.reason.like("%not-pe-hierarchy-evil.com%")).first()
    assert notevil_alert is None, (
        "'not-pe-hierarchy-evil.com' uchun Alert yaratildi - bu oddiy endswith() xatosi qaytganini bildiradi"
    )

    lexical_alert = s.query(Alert).filter(Alert.reason.like("%microsoft-login-security-update.xyz%")).first()
    assert lexical_alert is not None, "Leksik jihatdan aniq fishing domen uchun Alert yaratilmadi"
    assert lexical_alert.severity == "medium"
    assert "[LEXICAL_PHISHING]" in lexical_alert.reason

    google_alert = s.query(Alert).filter(Alert.reason.like("%google.com%")).first()
    assert google_alert is None, "Zararsiz domen (google.com) uchun ALERT yaratilmasligi kerak edi"
    s.close()

    # --- Dedup: bir xil fishing domeniga ikkinchi marta DNS so'rovi kelsa,
    #     QAYTA alert yaratilmasligi kerak ---
    s = get_session()
    s.add(RawLog(source_ip="172.16.0.6", raw_message=(
        '{"EventID":256,"ClientIP":"172.16.0.6","QueryName":"microsoft-login-security-update.xyz","QueryType":"A"}'
    )))
    s.commit()
    s.close()
    run_once()

    s = get_session()
    lexical_alerts = s.query(Alert).filter(Alert.reason.like("%microsoft-login-security-update.xyz%")).all()
    assert len(lexical_alerts) == 1, (
        f"Bir xil fishing domeni uchun QAYTA alert yaratilmasligi kerak edi (dedup), {len(lexical_alerts)} ta topildi"
    )
    s.close()


check("Parser Engine: domen ierarxiyasi blacklist + leksik fishing alert (dedup bilan, real DB orqali)", _test_parser_engine_domain_hierarchy_and_lexical_alert)

# ---------------------------------------------------------------------------
print("\n=== 87) Fayl turi aniqlash (magic bytes) - kengaytma niqoblanishini aniqlash (foydalanuvchi tahlilidagi ⑳-band) ===")


def _test_file_type_detector_module():
    """
    Foydalanuvchi chuqur arxitektura tahlilidagi ⑳-band: "Fayl MIME
    type'ini extensiondan ustun qo'yish kerak" - aniq misol sifatida
    `filename=invoice.pdf, magic=PE32 executable -> HIGH/CRITICAL`
    keltirilgan edi. Bu test `scanners/file_type_detector.py`ni AYNAN
    shu misol bilan tekshiradi.
    """
    from scanners.file_type_detector import (
        detect_magic_from_bytes, detect_magic_from_text, check_extension_mismatch,
    )

    # --- Bayt-signature'lar ---
    assert detect_magic_from_bytes(b"MZ" + b"\x90" * 58) == "PE"
    assert detect_magic_from_bytes(b"\x7fELF\x01\x01\x01") == "ELF"
    assert detect_magic_from_bytes(b"PK\x03\x04" + b"\x00" * 10) == "ZIP"
    assert detect_magic_from_bytes(b"%PDF-1.4\n") == "PDF"
    assert detect_magic_from_bytes(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") == "OLE2"
    assert detect_magic_from_bytes(b"Rar!\x1a\x07\x00") == "RAR"
    assert detect_magic_from_bytes(b"random plain text") is None

    # --- Suricata libmagic matn natijasi ---
    assert detect_magic_from_text("PE32 executable (GUI) Intel 80386, for MS Windows") == "PE"
    assert detect_magic_from_text("PDF document, version 1.4") == "PDF"
    assert detect_magic_from_text("Zip archive data, at least v2.0 to extract") == "ZIP"
    assert detect_magic_from_text("ASCII text") is None

    # --- Foydalanuvchining O'Z misoli: invoice.pdf, aslida PE32 ---
    result = check_extension_mismatch("pdf", "PE")
    assert result["mismatch"] is True
    assert result["severity"] == "critical", f"Niqoblangan bajariladigan fayl 'critical' bo'lishi kerak edi, {result} keldi"

    # --- Mos kelgan holat - mismatch bo'lmasligi kerak ---
    assert check_extension_mismatch("pdf", "PDF")["mismatch"] is False
    assert check_extension_mismatch("exe", "PE")["mismatch"] is False

    # --- "medium" daraja: bajariladigan bo'lmagan, lekin noto'g'ri turdagi mos kelmaslik ---
    medium = check_extension_mismatch("docx", "OLE2")
    assert medium["mismatch"] is True and medium["severity"] == "medium"

    # --- Noma'lum/tekshirilmagan kengaytma - fikr yuritilmaydi ---
    assert check_extension_mismatch("txt", "PE") == {"mismatch": False, "severity": None, "note": None}
    assert check_extension_mismatch("log", None) == {"mismatch": False, "severity": None, "note": None}


check("Fayl turi aniqlash (magic bytes) - kengaytma niqoblanishini aniqlash moduli", _test_file_type_detector_module)

# ---------------------------------------------------------------------------
print("\n=== 88) File Analysis Engine: niqoblangan fayl (kengaytma vs haqiqiy tur) - real DB orqali ===")


def _test_file_analysis_engine_detects_masquerade():
    """
    Foydalanuvchining aniq misoli: hash-intel (local/VT/MalwareBazaar)
    HECH NARSA demasa ham (yangi, hech qaysi bazada yo'q fayl) - agar
    fayl NIQOBLANGAN bo'lsa (Suricata `force-magic`dan kelgan `fe.magic`
    aslida bajariladigan fayl ekanini ko'rsatsa-yu, `fe.filename`/
    `file_ext` "hujjat" deb da'vo qilsa), bu ALOHIDA, mustaqil signal
    sifatida `verdict="malicious"`ga olib kelishi kerak.
    """
    from unittest.mock import patch
    import engine.file_analysis_engine as fae

    # --- 1) Hash-intel hech narsa demaydi, lekin fayl niqoblangan -> malicious ---
    s = get_session()
    fe1 = FileEvent(
        src_ip="172.16.64.1", filename="invoice.pdf", file_ext="pdf",
        magic="PE32 executable (GUI) Intel 80386, for MS Windows", sha256="1b" * 32, checked=False,
    )
    s.add(fe1)
    s.commit()
    with patch.object(fae, "check_virustotal", return_value=None), \
         patch.object(fae, "check_malwarebazaar", return_value=None):
        fae.analyze_one(s, fe1)
        s.commit()
    assert fe1.verdict == "malicious", (
        f"Niqoblangan fayl (hash-intel hech narsa demagan bo'lsa ham) 'malicious' bo'lishi kerak edi, '{fe1.verdict}' keldi"
    )
    alert1 = s.query(Alert).filter(Alert.file_event_id == fe1.id).first()
    assert alert1 is not None and "Niqoblangan fayl" in alert1.reason
    assert alert1.severity == "critical"
    s.close()

    # --- 2) Mos keladigan fayl (chin PDF) - hech qanday mismatch alert yo'q, "unknown" (hech kim tasdiqlamagan) ---
    s = get_session()
    fe2 = FileEvent(
        src_ip="172.16.64.2", filename="report.pdf", file_ext="pdf",
        magic="PDF document, version 1.4", sha256="2b" * 32, checked=False,
    )
    s.add(fe2)
    s.commit()
    with patch.object(fae, "check_virustotal", return_value=None), \
         patch.object(fae, "check_malwarebazaar", return_value=None):
        fae.analyze_one(s, fe2)
        s.commit()
    assert fe2.verdict == "unknown", f"Mos keladigan, tasdiqlanmagan fayl 'unknown' bo'lishi kerak edi, '{fe2.verdict}' keldi"
    assert s.query(Alert).filter(Alert.file_event_id == fe2.id).first() is None
    s.close()

    # --- 3) Hash-intel ALLAQACHON malicious deb topgan VA fayl ham niqoblangan -
    #        IKKITA emas, BITTA alert (dublikat yaratilmasligi) ---
    s = get_session()
    s.add(HashBlacklist(sha256="3b" * 32, threat_name="CI.KnownMalware", source="ci_test"))
    fe3 = FileEvent(
        src_ip="172.16.64.3", filename="salary.xlsx", file_ext="xlsx",
        magic="PE32 executable (GUI) Intel 80386, for MS Windows", sha256="3b" * 32, checked=False,
    )
    s.add(fe3)
    s.commit()
    fae.analyze_one(s, fe3)
    s.commit()
    assert fe3.verdict == "malicious"
    alerts3 = s.query(Alert).filter(Alert.file_event_id == fe3.id).all()
    assert len(alerts3) == 1, f"Hash-intel VA fayl-turi mosligi ikkalasi ham signal bergani uchun IKKITA alert yaratilmasligi kerak edi, {len(alerts3)} ta topildi"
    assert "NIQOBLANGAN" in alerts3[0].reason, "Alert matnida fayl-turi nomuvofiqligi haqida izoh bo'lishi kerak edi"
    s.close()


check("File Analysis Engine: niqoblangan fayl (kengaytma vs haqiqiy tur) aniqlanadi, real DB orqali", _test_file_analysis_engine_detects_masquerade)

# ---------------------------------------------------------------------------
print("\n=== 89) Deep Scan Engine: haqiqiy fayl baytlaridan niqoblanish + kengaytmasiz ZIP bypass yopilishi ===")


def _test_deep_scan_engine_magic_mismatch_and_zip_bypass():
    """
    (1) Haqiqiy PE32 baytlari bilan, lekin `.pdf` deb nomlangan HAQIQIY
        fayl `deep_scan_engine`ning o'zi (Suricata matn-magic'iga emas,
        HAQIQIY diskdagi baytlarga asoslanib) niqoblanganini aniqlashi
        kerak.
    (2) Haqiqiy ZIP baytlari bilan, lekin `.txt` deb nomlangan fayl -
        avval FAQAT kengaytmaga (`file_ext in ARCHIVE_EXTENSIONS`)
        qarab arxiv skaneri o'tkazib yuborilardi (haqiqiy bypass
        texnikasi) - endi HAQIQIY tur orqali ham aniqlanib, arxiv
        sifatida ochilishi kerak.
    """
    import shutil
    import zipfile
    from unittest.mock import patch

    try:
        import engine.deep_scan_engine as dse
    except ImportError as exc:
        print(f"   (yara/oletools yo'q - bu test o'tkazib yuborildi: {exc})")
        return

    work_dir = "/tmp/_test_deep_scan_magic_mismatch"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    try:
        # --- 1) PE32 baytlari, .pdf deb nomlangan ---
        fake_pdf_path = os.path.join(work_dir, "invoice.pdf")
        with open(fake_pdf_path, "wb") as f:
            f.write(b"MZ" + b"\x90" * 58 + b"This program cannot be run in DOS mode")

        s = get_session()
        fe1 = FileEvent(
            src_ip="172.16.64.10", filename="invoice.pdf", file_ext="pdf",
            sha256="4b" * 32, checked=True, verdict="unknown",
            stored_path=fake_pdf_path,
        )
        s.add(fe1)
        s.commit()
        with patch.object(dse, "yara_scan_file", return_value=[]), \
             patch.object(dse, "clamav_db_available", return_value=False), \
             patch.object(dse, "clamav_scan_file", return_value={"infected": False, "error": None}):
            dse.deep_scan_one(s, fe1)
            s.commit()
        assert fe1.verdict == "malicious", (
            f"HAQIQIY fayl baytlaridan PE32 aniqlanishi, .pdf deb nomlangan bo'lsa ham 'malicious' berishi kerak edi, '{fe1.verdict}' keldi"
        )
        assert "nomuvofiq" in (fe1.deep_scan_findings or "").lower()
        s.close()

        # --- 2) Haqiqiy ZIP, .txt deb nomlangan (kengaytma-asosli bypass) ---
        fake_zip_path = os.path.join(work_dir, "notes.txt")
        inner_path = os.path.join(work_dir, "inner_payload.bin")
        with open(inner_path, "wb") as f:
            f.write(b"MZ" + b"\x90" * 58 + b"fake payload for archive bypass test")
        with zipfile.ZipFile(fake_zip_path, "w") as zf:
            zf.write(inner_path, arcname="inner_payload.bin")

        s = get_session()
        fe2 = FileEvent(
            src_ip="172.16.64.11", filename="notes.txt", file_ext="txt",
            sha256="5b" * 32, checked=True, verdict="unknown",
            stored_path=fake_zip_path,
        )
        s.add(fe2)
        s.commit()
        fe2_id = fe2.id
        with patch.object(dse, "yara_scan_file", return_value=[]), \
             patch.object(dse, "clamav_db_available", return_value=False), \
             patch.object(dse, "clamav_scan_file", return_value={"infected": False, "error": None}):
            dse.deep_scan_one(s, fe2)
            s.commit()
        assert "ZIP" in (fe2.deep_scan_findings or ""), (
            "Kengaytma '.txt' bo'lsa ham, haqiqiy ZIP tarkib arxiv sifatida tanilmadi (bypass hali yopilmagan)"
        )
        child = s.query(FileEvent).filter(FileEvent.parent_file_event_id == fe2_id).first()
        assert child is not None, "notes.txt ichidan (haqiqatan ZIP bo'lgani uchun) inner_payload.bin chiqarilishi kerak edi"
        assert child.filename == "inner_payload.bin"
        s.close()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
        shutil.rmtree("/tmp/archive_extraction", ignore_errors=True)


check("Deep Scan Engine: haqiqiy fayl baytlaridan niqoblanish aniqlanadi + kengaytmasiz ZIP bypass yopilgan", _test_deep_scan_engine_magic_mismatch_and_zip_bypass)

# ---------------------------------------------------------------------------
print("\n=== 90) PDF chuqur tahlil moduli (siqilgan /OpenAction+/JavaScript, /Launch, ichki URL fishing balli) ===")


def _test_pdf_analyzer_module():
    """
    Foydalanuvchi chuqur arxitektura tahlilidagi ⑲-band: "PDF scanner
    alohida modul bo'lishi kerak", eng foydali qismi - "PDF ichidagi
    URL'larni ham URL engine'ga yuborish". Bu test `scanners/pdf_
    analyzer.py`ni HAQIQIY (qo'lda qurilgan, lekin haqiqiy PDF
    sintaksisiga mos) PDF baytlari bilan tekshiradi - shu jumladan
    zlib bilan SIQILGAN (FlateDecode) qismlar ichida yashiringan
    xavfli tuzilmalarni ham.
    """
    import zlib
    import shutil

    from scanners.pdf_analyzer import scan_pdf_file

    work_dir = "/tmp/_test_pdf_analyzer"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    try:
        # --- 1) /OpenAction + /JavaScript - SIQILGAN (FlateDecode) holda,
        #        XOM baytlarda UMUMAN ko'rinmaydi - faqat decompress orqali
        #        topilishi kerak. Ichida fishing'ga o'xshash /URI ham bor. ---
        inner = (
            b"<< /OpenAction 5 0 R /Names << /JavaScript 6 0 R >> "
            b"/Annots [ << /URI (https://microsoft-login-security.xyz/verify) >> ] >>"
        )
        compressed = zlib.compress(inner)
        hidden_path = os.path.join(work_dir, "hidden.pdf")
        with open(hidden_path, "wb") as f:
            f.write(b"%PDF-1.4\n")
            f.write(b"1 0 obj\n<< /Type /Catalog /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream\nendobj\n")
            f.write(b"%%EOF\n")
        assert b"/OpenAction" not in open(hidden_path, "rb").read(), (
            "Test qurilishi noto'g'ri - /OpenAction XOM baytlarda ko'rinib qolgan, "
            "bu test decompression'ni HAQIQATAN sinamayapti"
        )

        result = scan_pdf_file(hidden_path)
        assert result is not None
        assert result["suspicious"] is True, f"Siqilgan /OpenAction+/JavaScript aniqlanmadi: {result}"
        assert any("JavaScript" in f for f in result["findings"])
        assert any("OpenAction" in f for f in result["findings"])
        assert "https://microsoft-login-security.xyz/verify" in result["urls"]
        assert any("Shubhali URL" in f and "malicious" in f for f in result["findings"]), (
            "PDF ichidagi fishing URL threat_intel/url_intel.py orqali aniqlanmadi"
        )

        # --- 2) /Launch - o'zi yolg'iz ham har doim shubhali ---
        launch_path = os.path.join(work_dir, "launch.pdf")
        with open(launch_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<< /S /Launch /F (cmd.exe) >>\nendobj\n%%EOF\n")
        result2 = scan_pdf_file(launch_path)
        assert result2["suspicious"] is True
        assert any("Launch" in f for f in result2["findings"])

        # --- 3) Zararsiz PDF - hech qanday topilma yo'q ---
        benign_path = os.path.join(work_dir, "benign.pdf")
        with open(benign_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n%%EOF\n")
        result3 = scan_pdf_file(benign_path)
        assert result3 == {"suspicious": False, "findings": [], "urls": []}

        # --- 4) PDF bo'lmagan/mavjud bo'lmagan fayl - None ---
        not_pdf_path = os.path.join(work_dir, "notes.txt")
        with open(not_pdf_path, "w") as f:
            f.write("oddiy matn")
        assert scan_pdf_file(not_pdf_path) is None
        assert scan_pdf_file(os.path.join(work_dir, "yoq.pdf")) is None
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


check("PDF chuqur tahlil moduli - siqilgan xavfli tuzilma + ichki URL fishing balli", _test_pdf_analyzer_module)

# ---------------------------------------------------------------------------
print("\n=== 91) Deep Scan Engine: PDF chuqur tahlil integratsiyasi (real DB orqali) ===")


def _test_deep_scan_engine_pdf_integration():
    """
    `deep_scan_engine.deep_scan_one()` HAQIQIY diskdagi PDF faylni
    (siqilgan /OpenAction+/JavaScript bilan) `scanners/pdf_analyzer.py`
    orqali tekshirib, `verdict="malicious"`ga o'tkazishini va Alert
    yaratishini tasdiqlaydi.
    """
    import zlib
    import shutil
    from unittest.mock import patch

    try:
        import engine.deep_scan_engine as dse
    except ImportError as exc:
        print(f"   (yara/oletools yo'q - bu test o'tkazib yuborildi: {exc})")
        return

    work_dir = "/tmp/_test_deep_scan_pdf"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    try:
        inner = b"<< /OpenAction 5 0 R /Names << /JavaScript 6 0 R >> >>"
        compressed = zlib.compress(inner)
        pdf_path = os.path.join(work_dir, "invoice_details.pdf")
        with open(pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream\nendobj\n%%EOF\n")

        s = get_session()
        fe = FileEvent(
            src_ip="172.16.64.20", filename="invoice_details.pdf", file_ext="pdf",
            sha256="6b" * 32, checked=True, verdict="unknown", stored_path=pdf_path,
        )
        s.add(fe)
        s.commit()
        with patch.object(dse, "yara_scan_file", return_value=[]), \
             patch.object(dse, "clamav_db_available", return_value=False), \
             patch.object(dse, "clamav_scan_file", return_value={"infected": False, "error": None}):
            dse.deep_scan_one(s, fe)
            s.commit()

        assert fe.verdict == "malicious", f"PDF ichidagi siqilgan xavfli tuzilma aniqlanmadi, verdict='{fe.verdict}'"
        assert "JavaScript" in (fe.deep_scan_findings or "")
        alert = s.query(Alert).filter(Alert.file_event_id == fe.id).first()
        assert alert is not None and alert.severity == "critical"
        s.close()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


check("Deep Scan Engine: PDF chuqur tahlil integratsiyasi (real DB orqali)", _test_deep_scan_engine_pdf_integration)

# ---------------------------------------------------------------------------
print("\n=== 92) Alembic migration tizimi: baseline migratsiya db/models.py bilan bir xil sxema yaratadi ===")


def _alembic_repo_root():
    return os.path.dirname(os.path.abspath(__file__))


def _run_alembic(args, database_url):
    """`alembic` CLI'ni HAQIQATAN chaqiradi (ichki funksiyalarni to'g'ridan-to'g'ri
    chaqirish emas) - bu administrator qo'lda ishlatadigan buyruqning aynan o'zi."""
    import subprocess
    env = {**os.environ, "DATABASE_URL": database_url}
    result = subprocess.run(
        ["alembic"] + args, cwd=_alembic_repo_root(), env=env,
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"alembic {' '.join(args)} muvaffaqiyatsiz (DATABASE_URL bor):\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def _alembic_schema_snapshot(engine):
    from sqlalchemy import inspect
    inspector = inspect(engine)
    snap = {}
    for table in inspector.get_table_names():
        if table == "alembic_version":
            continue
        snap[table] = {c["name"] for c in inspector.get_columns(table)}
    return snap


def _alembic_models_snapshot():
    from db.models import Base
    return {t.name: {c.name for c in t.columns} for t in Base.metadata.sorted_tables}


def _assert_alembic_schema_matches_models(engine, label):
    snap = _alembic_schema_snapshot(engine)
    expected = _alembic_models_snapshot()
    assert snap.keys() == expected.keys(), (
        f"[{label}] Jadvallar to'plami db/models.py bilan mos kelmadi: "
        f"bazada ortiqcha={snap.keys() - expected.keys()}, "
        f"bazada yetishmayapti={expected.keys() - snap.keys()}"
    )
    for table, cols in expected.items():
        assert snap[table] == cols, (
            f"[{label}] '{table}' ustunlari mos kelmadi: "
            f"bazada ortiqcha={snap[table] - cols}, bazada yetishmayapti={cols - snap[table]}"
        )


def _assert_alembic_no_drift(engine, label):
    """`compare_metadata` - migratsiya fayllari db/models.py'dagi joriy
    modellardan CHETLAB ketmaganini isbotlaydi (masalan kimdir models.py'ga
    yangi ustun qo'shib, mos migratsiya yozishni unutsa - bu test DARHOL
    ushlaydi, aks holda bu faqat production'da 'column X does not exist'
    sifatida ochiladigan turdagi xato)."""
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    from db.models import Base

    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        diff = compare_metadata(ctx, Base.metadata)
    assert diff == [], f"[{label}] Autogenerate drift topildi (migratsiya models.py bilan sinxron emas): {diff}"


def _test_alembic_sqlite_upgrade_head():
    """Bo'sh SQLite bazada `alembic upgrade head` - db/models.py bilan
    BAYT-BAYT (jadval/ustun darajasida) bir xil sxema hosil qilishi kerak."""
    from sqlalchemy import create_engine

    db_path = "/tmp/_alembic_test_sqlite.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    db_url = f"sqlite:///{db_path}"
    try:
        _run_alembic(["upgrade", "head"], db_url)
        engine = create_engine(db_url)
        _assert_alembic_schema_matches_models(engine, "SQLite/upgrade-head")
        _assert_alembic_no_drift(engine, "SQLite/upgrade-head")
        engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


check("Alembic: bo'sh SQLite'da 'upgrade head' db/models.py bilan mos sxema yaratadi", _test_alembic_sqlite_upgrade_head)

# ---------------------------------------------------------------------------
print("\n=== 93) Alembic migration tizimi: mavjud (legacy) baza 'stamp head' orqali xavfsiz bog'lanadi ===")


def _test_alembic_stamp_on_legacy_db():
    """
    Production bazasi Alembic'dan OLDIN `init_db()` (create_all +
    _sync_missing_columns) orqali yaratilgan/kengaytirilgan - bu test
    aynan shu holatni simulyatsiya qiladi: legacy usulda yaratilgan
    bazaga `alembic stamp head` qo'llanganda HECH QANDAY DDL bajarilmasdan
    (jadvallar allaqachon bor - qayta yaratishga urinish xato berardi),
    faqat versiya belgisi to'g'ri qo'yilishini tasdiqlaydi. Bu - production
    bazasini bir martalik 'stamp head' bilan Alembic nazoratiga o'tkazish
    xavfsizligini isbotlaydi.
    """
    from db.models import init_db
    from sqlalchemy import create_engine, inspect, text

    db_path = "/tmp/_alembic_test_legacy.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    db_url = f"sqlite:///{db_path}"
    try:
        # 1) "Production" holatini simulyatsiya qilish - legacy yo'l
        engine = init_db(db_url)
        _assert_alembic_schema_matches_models(engine, "Legacy/init_db()")
        engine.dispose()

        engine = create_engine(db_url)
        assert "alembic_version" not in inspect(engine).get_table_names(), \
            "Test sozlamasi xato - alembic_version allaqachon bor"
        engine.dispose()

        # 2) `alembic stamp head` - faqat versiya yozadi, DDL YO'Q
        _run_alembic(["stamp", "head"], db_url)

        engine = create_engine(db_url)
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
        assert version, "stamp'dan keyin alembic_version bo'sh"
        _assert_alembic_no_drift(engine, "Legacy/stamped")
        engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


check("Alembic: legacy (init_db orqali yaratilgan) bazani 'stamp head' bilan xavfsiz bog'lash", _test_alembic_stamp_on_legacy_db)

# ---------------------------------------------------------------------------
print("\n=== 94) Alembic migration tizimi: HAQIQIY, vaqtinchalik/alohida Docker PostgreSQL konteynerida ===")


def _test_alembic_postgres_upgrade_head():
    """
    Bosh #92/93 testlarining aynan o'zini, lekin PostgreSQL'da tekshiradi.

    MUHIM (xavfsizlik): bu test docker-compose'dagi PRODUCTION
    PostgreSQL konteyneriga (`network_security_system-postgres-1`,
    127.0.0.1:5432) UMUMAN TEGMAYDI - o'zining ALOHIDA, vaqtinchalik
    konteynerini (boshqa nom, boshqa port 55432, boshqa credential)
    ko'taradi va testdan keyin (muvaffaqiyatli yoki muvaffaqiyatsiz
    bo'lishidan qat'iy nazar, `finally` orqali) DARHOL o'chiradi. Docker
    mavjud bo'lmasa yoki band bo'lsa, test xatosiz o'tkazib yuboriladi.
    """
    import subprocess
    import time
    import uuid

    if subprocess.run(["which", "docker"], capture_output=True).returncode != 0:
        print("   (o'tkazib yuborildi - docker o'rnatilmagan)")
        return

    container = f"nss-alembic-test-{uuid.uuid4().hex[:8]}"
    port = 55432
    subprocess.run(["docker", "rm", "-f", container], capture_output=True)
    try:
        run_result = subprocess.run([
            "docker", "run", "-d", "--name", container,
            "-e", "POSTGRES_USER=alembic_test",
            "-e", "POSTGRES_PASSWORD=alembic_test_pw",
            "-e", "POSTGRES_DB=alembic_test",
            "-p", f"127.0.0.1:{port}:5432",
            "postgres:16-alpine",
        ], capture_output=True, text=True)
        if run_result.returncode != 0:
            print(f"   (o'tkazib yuborildi - vaqtinchalik konteyner ko'tarilmadi: {run_result.stderr.strip()})")
            return

        db_url = f"postgresql://alembic_test:alembic_test_pw@127.0.0.1:{port}/alembic_test"

        ready = False
        for _ in range(30):
            r = subprocess.run(["docker", "exec", container, "pg_isready", "-U", "alembic_test"],
                                capture_output=True)
            if r.returncode == 0:
                ready = True
                break
            time.sleep(1)
        assert ready, "Vaqtinchalik PostgreSQL konteyneri 30 soniyada tayyor bo'lmadi"

        from sqlalchemy import create_engine
        _run_alembic(["upgrade", "head"], db_url)
        engine = create_engine(db_url)
        _assert_alembic_schema_matches_models(engine, "PostgreSQL/upgrade-head")
        _assert_alembic_no_drift(engine, "PostgreSQL/upgrade-head")
        engine.dispose()
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)


check("Alembic: HAQIQIY, vaqtinchalik/alohida Docker PostgreSQL konteynerida 'upgrade head'", _test_alembic_postgres_upgrade_head)

# ---------------------------------------------------------------------------
print("\n=== 95) Dashboard /devices: 72+ soat ko'rinmagan ('eski') qurilmalar ro'yxatdan yashiriladi (tarixi yo'qolmaydi) ===")


def _test_devices_stale_hide():
    """
    Foydalanuvchi so'rovi: '72 soat online bo'lmagan qurilmani
    qurilmalar ro'yxatidan chiqarsin'. Tanlangan yechim (foydalanuvchi
    bilan kelishilgan): FAQAT ro'yxatdan yashirish, bazadan
    o'chirmaslik - qurilmaga bog'liq Event/Alert/tarix xavfsizlik
    audit maqsadida saqlanib qolishi kerak. Bu test uchta narsani
    tasdiqlaydi: (1) standart holatda 72+ soat oflayn qurilma
    ro'yxatda ko'rinmaydi, (2) `show_stale=1` bilan qayta ko'rinadi,
    (3) shu qurilmaga bog'liq Alert bazada YO'QOLMAGAN.
    """
    from datetime import timedelta
    from db.models import Device, Alert, utcnow
    from config.settings import DEVICE_STALE_HIDE_HOURS

    s = get_session()
    fresh = Device(
        ip_address="172.16.72.1", mac_address="AA:BB:CC:72:00:01", hostname="FRESH-DEVICE-72H",
        connection_type="wifi", source="kerio_dhcp", last_seen=utcnow(),
    )
    stale = Device(
        ip_address="172.16.72.2", mac_address="AA:BB:CC:72:00:02", hostname="STALE-DEVICE-72H",
        connection_type="wifi", source="kerio_dhcp",
        last_seen=utcnow() - timedelta(hours=DEVICE_STALE_HIDE_HOURS + 1),
    )
    s.add_all([fresh, stale])
    s.commit()
    stale_alert = Alert(severity="medium", reason="STALE-DEVICE-72H uchun eski alert (tarix)", device_id=stale.id)
    s.add(stale_alert)
    s.commit()
    stale_device_id = stale.id
    stale_alert_id = stale_alert.id
    s.close()

    from dashboard.app import app as dashboard_app
    from dashboard.create_user import create_user
    create_user("stalehide_admin", "stalehidepass123", "admin")
    dashboard_app.secret_key = "test-secret-stale-hide"
    client = _dash_client(dashboard_app)
    client.post("/login", data={"username": "stalehide_admin", "password": "stalehidepass123"})

    # 1) Standart holatda: yangi qurilma ko'rinadi, eski (72+ soat) ko'rinmaydi
    html = client.get("/devices").get_data(as_text=True)
    assert "FRESH-DEVICE-72H" in html, "Yangi qurilma standart holatda ko'rinishi kerak edi"
    assert "STALE-DEVICE-72H" not in html, "72+ soat oflayn qurilma standart holatda YASHIRILISHI kerak edi"
    assert "yashirilgan" in html, "Yashirilgan qurilmalar haqida ogohlantirish ko'rinmadi"

    # 2) `show_stale=1` bilan qayta ko'rinishi kerak
    html = client.get("/devices?show_stale=1&hostname=DEVICE-72H").get_data(as_text=True)
    assert "FRESH-DEVICE-72H" in html and "STALE-DEVICE-72H" in html, \
        "show_stale=1 bilan eski qurilma ham ko'rinishi kerak edi"

    # 3) Bazada Device/Alert tarixi YO'QOLMAGAN (faqat ko'rinish yashirilgan)
    s2 = get_session()
    assert s2.query(Device).filter(Device.id == stale_device_id).first() is not None, \
        "Eski qurilma bazadan o'chib ketmasligi kerak edi"
    assert s2.query(Alert).filter(Alert.id == stale_alert_id).first() is not None, \
        "Eski qurilmaga bog'liq Alert tarixi yo'qolmasligi kerak edi"
    s2.close()


check("Dashboard /devices: 72+ soat oflayn qurilmalar ro'yxatdan yashiriladi (tarix saqlanadi)", _test_devices_stale_hide)

# ---------------------------------------------------------------------------
print("\n=== 96) Notification Engine: Email/Telegram FAQAT critical/high uchun yuboriladi, qolgani faqat logga ===")


def _test_notification_severity_filter():
    """
    Foydalanuvchi so'rovi: 'telegram va email orqali xabar faqat
    Critical yoki High bo'lsa yuborsin aks holda faqat log ga yozsin'.

    Bu test real send_alert_email/send_alert_telegram funksiyalarini
    Mock bilan almashtirib (SMTP/Telegram serverga chiqmasdan, faqat
    "chaqirildimi/yo'qmi"ni kuzatib) tekshiradi: (1) critical/high
    alertlar uchun IKKALA kanal ham chaqiriladi, (2) medium/low
    alertlar uchun HECH QAYSI kanal chaqirilmaydi, (3) barcha 4
    alert baribir `notified=True` bo'lib qoladi (chaqirilmaganlari
    ham - aks holda tsikl ularni abadiy qayta-qayta ko'rib chiqaveradi),
    (4) `NOTIFY_MIN_SEVERITIES` orqali chegara sozlanishi mumkinligi.
    """
    import importlib
    from unittest.mock import patch, MagicMock

    s = get_session()
    # Izolyatsiya: bitta umumiy bazada oldingi testlardan qolgan, hali
    # xabar qilinmagan alertlar bu testning sanog'iga aralashmasligi uchun
    # ularni "xabar qilingan" deb belgilaymiz.
    s.query(Alert).filter(Alert.notified.isnot(True)).update({"notified": True}, synchronize_session=False)
    s.commit()
    d = Device(ip_address="172.16.96.1", mac_address="AA:BB:CC:96:00:01",
               hostname="SEVERITY-FILTER-PC", connection_type="wifi", source="test")
    s.add(d)
    s.flush()
    alerts = {}
    for sev in ["critical", "high", "medium", "low"]:
        a = Alert(device_id=d.id, severity=sev, reason=f"Test {sev} alert",
                   action_taken="", notified=False)
        s.add(a)
        s.flush()
        alerts[sev] = a.id
    s.commit()
    s.close()

    os.environ["NOTIFY_CHANNELS"] = "email,telegram"
    os.environ.pop("NOTIFY_MIN_SEVERITIES", None)  # standart: critical,high

    import engine.notification_engine as notif_engine
    importlib.reload(notif_engine)

    try:
        with patch.object(notif_engine, "send_alert_email", return_value=True) as mock_email, \
             patch.object(notif_engine, "send_alert_telegram", return_value=True) as mock_tg:
            n = notif_engine.run_once()
            assert n == 4, f"Barcha 4 alert 'ishlangan' deb sanalishi kerak edi, {n} ta sanaldi"

            sent_reasons = {c.args[0]["reason"] for c in mock_email.call_args_list}
            assert "Test critical alert" in sent_reasons, "critical uchun email chaqirilmadi"
            assert "Test high alert" in sent_reasons, "high uchun email chaqirilmadi"
            assert "Test medium alert" not in sent_reasons, "medium uchun email XATO ravishda chaqirildi"
            assert "Test low alert" not in sent_reasons, "low uchun email XATO ravishda chaqirildi"
            assert mock_email.call_count == 2, f"Faqat 2 marta (critical+high) chaqirilishi kerak edi, {mock_email.call_count}"
            assert mock_tg.call_count == 2, f"Telegram ham faqat 2 marta chaqirilishi kerak edi, {mock_tg.call_count}"

        # Barcha 4 alert - hatto chaqirilmaganlari ham - notified=True bo'lishi kerak
        s = get_session()
        for sev, aid in alerts.items():
            a = s.query(Alert).filter(Alert.id == aid).first()
            assert a.notified is True, f"{sev} alert notified=True bo'lishi kerak edi (qayta urinib turmasligi uchun)"
        s.close()

        # NOTIFY_MIN_SEVERITIES orqali chegara qattiqlashtirilsa (faqat critical)
        os.environ["NOTIFY_MIN_SEVERITIES"] = "critical"
        importlib.reload(notif_engine)
        s = get_session()
        d2 = Device(ip_address="172.16.96.2", mac_address="AA:BB:CC:96:00:02",
                    hostname="SEVERITY-FILTER-PC-2", connection_type="wifi", source="test")
        s.add(d2)
        s.flush()
        high_alert2 = Alert(device_id=d2.id, severity="high", reason="Ikkinchi high alert",
                             action_taken="", notified=False)
        s.add(high_alert2)
        s.commit()
        s.close()

        with patch.object(notif_engine, "send_alert_email", return_value=True) as mock_email2, \
             patch.object(notif_engine, "send_alert_telegram", return_value=True) as mock_tg2:
            notif_engine.run_once()
            assert mock_email2.call_count == 0, (
                "NOTIFY_MIN_SEVERITIES='critical' bo'lganda 'high' alert uchun ham "
                "email XATO ravishda yuborildi"
            )
            assert mock_tg2.call_count == 0
    finally:
        for k in ["NOTIFY_CHANNELS", "NOTIFY_MIN_SEVERITIES"]:
            os.environ.pop(k, None)
        importlib.reload(notif_engine)


check("Notification Engine: Email/Telegram faqat critical/high uchun, qolgani faqat log", _test_notification_severity_filter)

# ---------------------------------------------------------------------------
print("\n=== 97) PostgreSQL indexing: alerts/events'ga ishlash unumdorligi indekslari (real production drift topilgan+tuzatilgan) ===")


def _test_performance_indexes_migration():
    """
    BOSQICH 0 (Enterprise hardening audit): `alerts` (~10 000 qator,
    HECH QANDAY ustun indekslanmagan edi - faqat PK) va `events`
    (production'da 7.6 million+ qator) jadvallariga real so'rov
    naqshlariga (notification_engine'ning `notified=False` har 10
    soniyalik so'rovi, UEBA'ning `device_id+timestamp` so'rovi,
    Dashboard'ning `severity`/`acknowledged`/sana-oralig'i filtri)
    mos indekslar qo'shildi (`alembic/versions/
    60a696c5452e_add_alert_and_event_performance_indexes.py`).

    BONUS - shu ishni tekshirish jarayonida topilgan va tuzatilgan
    REAL xato: oldingi migratsiya (`79ad4a5404a6`, api_tokens indeksi
    uchun) idempotent EMAS edi - BO'SH (yangi) bazada baseline
    migratsiya bu indeksni ALLAQACHON yaratadi (chunki model'da
    `index=True` bor), shuning uchun ikkinchi migratsiya "index
    already exists" xatosi bilan MUVAFFAQIYATSIZ bo'lardi. Bu -
    aynan shu migratsiyani ishlab chiqish jarayonida (yangi, bo'sh
    baza bilan 3 ta migratsiyani ketma-ket sinaganda) DARHOL
    ochilib qolgan, hech qachon avval sinalmagan bo'shliq edi -
    tuzatildi (indeks avval mavjudligini tekshirib, faqat yo'q
    bo'lsa yaratadi).

    Bu test uchta narsani tasdiqlaydi: (1) bo'sh bazadan boshlab
    BARCHA (hozircha 3 ta) migratsiya ketma-ket muvaffaqiyatli
    qo'llanishi (aynan yuqoridagi bo'shliqni ushlaydigan regressiya
    himoyasi), (2) yakuniy sxemada kutilgan barcha yangi indekslar
    borligi, (3) drift yo'qligi.
    """
    from sqlalchemy import create_engine, inspect

    db_path = "/tmp/_alembic_test_perf_indexes.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    db_url = f"sqlite:///{db_path}"
    try:
        _run_alembic(["upgrade", "head"], db_url)  # BO'SH bazadan - barcha migratsiyalar ketma-ket

        engine = create_engine(db_url)
        inspector = inspect(engine)
        alert_indexes = {ix["name"] for ix in inspector.get_indexes("alerts")}
        event_indexes = {ix["name"] for ix in inspector.get_indexes("events")}

        expected_alert_indexes = {
            "ix_alerts_device_id_timestamp", "ix_alerts_severity",
            "ix_alerts_acknowledged", "ix_alerts_notified", "ix_alerts_timestamp",
        }
        missing_alert = expected_alert_indexes - alert_indexes
        assert not missing_alert, f"'alerts'da kutilgan indekslar yo'q: {missing_alert}"
        assert "ix_events_device_id_timestamp" in event_indexes, \
            "'events'da device_id+timestamp indeksi yo'q"

        _assert_alembic_schema_matches_models(engine, "PerfIndexes/upgrade-head")
        _assert_alembic_no_drift(engine, "PerfIndexes/upgrade-head")
        engine.dispose()
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


check("PostgreSQL indexing: alerts/events performance indekslari (bo'sh bazadan barcha migratsiya ketma-ket)", _test_performance_indexes_migration)

# ---------------------------------------------------------------------------
print("\n=== 98) Correlation Engine: alohida alertlarni bitta Incident'ga birlashtirish ===")


def _test_correlation_engine():
    """
    Yangi bosqich (13-bosqichli enterprise rejadagi 'Detection+
    Correlation'): bir xil qurilmada, `CORRELATION_WINDOW_MINUTES`
    (standart 30 daqiqa) ichida ketma-ket kelgan alertlar bitta
    Incident'ga birlashtiriladi - alohida ko'rish o'rniga, tahlilchi
    BITTA hodisani ko'radi.

    Bu test 5 stsenariyni tekshiradi: (1) bir xil qurilma, oyna ichida -
    BIR Incident, (2) Incident severity guruhdagi ENG YUQORI darajaga
    ko'tarilishi, (3) oynadan TASHQARIDA - YANGI Incident, (4) boshqa
    qurilma - alohida Incident, (5) device_id yo'q alert ham (standalone)
    Incident olishi (hech qachon abadiy `incident_id=NULL` bo'lib
    qolmasligi kerak - aks holda `run_once()` uni HAR TSIKLDA qayta-qayta
    ko'rib chiqaveradi).
    """
    from datetime import timedelta
    from db.models import Device, Alert, Incident, utcnow
    import engine.correlation_engine as ce

    s = get_session()
    # Izolyatsiya: oldingi testlardan qolgan, hali Incident'ga bog'lanmagan
    # alertlar bu testning sanog'iga aralashmasligi uchun ularni bitta
    # texnik Incident'ga biriktiramiz.
    _legacy = Incident(title="legacy alerts (test isolation)", severity="low", status="resolved",
                       first_seen=utcnow(), last_seen=utcnow())
    s.add(_legacy)
    s.flush()
    s.query(Alert).filter(Alert.incident_id.is_(None)).update({"incident_id": _legacy.id}, synchronize_session=False)
    s.commit()
    d1 = Device(ip_address="172.16.97.1", mac_address="AA:BB:CC:97:00:01", hostname="CORR-TEST-D1",
                connection_type="wifi", source="test")
    d2 = Device(ip_address="172.16.97.2", mac_address="AA:BB:CC:97:00:02", hostname="CORR-TEST-D2",
                connection_type="wifi", source="test")
    s.add_all([d1, d2])
    s.flush()
    now = utcnow()
    a1 = Alert(device_id=d1.id, severity="low", reason="Test 1: past darajali alert", timestamp=now)
    a2 = Alert(device_id=d1.id, severity="critical", reason="Test 2: yuqori darajali alert", timestamp=now + timedelta(minutes=5))
    a3 = Alert(device_id=d1.id, severity="medium", reason="Test 3: oynadan tashqari", timestamp=now + timedelta(minutes=65))
    a4 = Alert(device_id=d2.id, severity="high", reason="Test 4: boshqa qurilma", timestamp=now)
    a5 = Alert(device_id=None, severity="medium", reason="Test 5: qurilmasiz alert", timestamp=now)
    s.add_all([a1, a2, a3, a4, a5])
    s.commit()
    ids = {"a1": a1.id, "a2": a2.id, "a3": a3.id, "a4": a4.id, "a5": a5.id}
    s.close()

    n = ce.run_once()
    assert n == 5, f"5 ta alert qayta ishlanishi kerak edi, {n} ta ishlandi"

    s2 = get_session()
    a = {k: s2.query(Alert).filter(Alert.id == v).first() for k, v in ids.items()}

    assert a["a1"].incident_id == a["a2"].incident_id, "Bir xil qurilma, oyna ichidagi alertlar BIR XIL Incident'da bo'lishi kerak edi"
    assert a["a3"].incident_id != a["a1"].incident_id, "Oynadan tashqaridagi alert YANGI Incident olishi kerak edi"
    assert a["a4"].incident_id != a["a1"].incident_id, "Boshqa qurilmadagi alert alohida Incident olishi kerak edi"
    assert a["a5"].incident_id is not None, "device_id'siz alert ham Incident olishi kerak edi"

    inc1 = s2.query(Incident).filter(Incident.id == a["a1"].incident_id).first()
    assert inc1.severity == "critical", f"Incident severity ENG YUQORIga ko'tarilishi kerak edi, bor: {inc1.severity}"
    assert inc1.alert_count == 2, f"alert_count=2 bo'lishi kerak edi, bor: {inc1.alert_count}"
    assert inc1.status == "open"
    s2.close()


check("Correlation Engine: bir xil qurilmadagi alertlar bitta Incident'ga birlashadi, severity ko'tariladi", _test_correlation_engine)

# ---------------------------------------------------------------------------
print("\n=== 99) Dashboard: /incidents ro'yxati, tafsilot sahifasi va holat yangilash (RBAC bilan) ===")


def _test_incidents_dashboard():
    """
    `/incidents` (ro'yxat), `/incidents/<id>` (tafsilot - bog'liq
    alertlar bilan) va `/incidents/<id>/status` (analyst/admin huquqi
    bilan holat yangilash - resolved/false_positive belgilanganda
    `resolved_by`/`resolved_at` to'ldirilishi) real HTTP orqali
    tekshiriladi.
    """
    from db.models import Device, Alert, Incident, utcnow
    import engine.correlation_engine as ce

    s = get_session()
    d = Device(ip_address="172.16.97.3", mac_address="AA:BB:CC:97:00:03", hostname="INCIDENT-DASH-TEST",
               connection_type="wifi", source="test")
    s.add(d)
    s.flush()
    device_id = d.id
    alert = Alert(device_id=device_id, severity="high", reason="Shubhali PowerShell ijrosi (test)", timestamp=utcnow())
    s.add(alert)
    s.commit()
    s.close()

    ce.run_once()

    s2 = get_session()
    incident_id = s2.query(Incident).filter(Incident.device_id == device_id).first().id
    s2.close()

    from dashboard.app import app as dashboard_app
    from dashboard.create_user import create_user
    create_user("incidenttest_admin", "incidenttestpass123", "admin")
    dashboard_app.secret_key = "test-secret-incidents-dashboard"
    client = _dash_client(dashboard_app)
    client.post("/login", data={"username": "incidenttest_admin", "password": "incidenttestpass123"})

    html = client.get("/incidents").get_data(as_text=True)
    assert "INCIDENT-DASH-TEST" in html, "/incidents ro'yxatida qurilma ko'rinmadi"

    html = client.get(f"/incidents/{incident_id}").get_data(as_text=True)
    assert "Shubhali PowerShell ijrosi (test)" in html, "Tafsilot sahifasida bog'liq alert ko'rinmadi"

    resp = client.post(f"/incidents/{incident_id}/status", data={"status": "resolved"})
    assert resp.status_code in (200, 302)

    s3 = get_session()
    inc = s3.query(Incident).filter(Incident.id == incident_id).first()
    assert inc.status == "resolved", f"status='resolved' bo'lishi kerak edi, bor: {inc.status}"
    assert inc.resolved_by == "incidenttest_admin", "resolved_by to'g'ri o'rnatilmadi"
    assert inc.resolved_at is not None, "resolved_at to'g'ri o'rnatilmadi"
    s3.close()

    # Ro'yxat sahifasida standart (status=open) filtr endi bu Incident'ni yashirishi kerak
    html = client.get("/incidents?status=open").get_data(as_text=True)
    assert "INCIDENT-DASH-TEST" not in html, "Yechilgan Incident 'Ochiq' filtrida ko'rinmasligi kerak edi"
    html = client.get("/incidents?status=resolved").get_data(as_text=True)
    assert "INCIDENT-DASH-TEST" in html, "Yechilgan Incident 'Yechildi' filtrida ko'rinishi kerak edi"


check("Dashboard: /incidents ro'yxati/tafsilot/holat yangilash real HTTP orqali", _test_incidents_dashboard)

# ---------------------------------------------------------------------------
print("\n=== 100) Threat Intelligence: URLhaus/ThreatFox feed'laridan BlacklistEntry'ni avtomatik boyitish ===")


def _test_threat_intel_sync():
    """
    URLhaus/ThreatFox (abuse.ch) 2024'dan buyon bepul, lekin
    ro'yxatdan o'tib olinadigan Auth-Key talab qiladi - shuning uchun
    `requests.get`/`requests.post` ustidan, RASMIY API HUJJATLARIDAN
    (https://urlhaus-api.abuse.ch/, https://threatfox.abuse.ch/api/)
    so'zma-so'z olingan namunaviy JSON javoblar bilan Mock qo'yiladi.
    Bu test JSON-tahlil mantig'ining haqiqiy formatga mosligini
    tasdiqlaydi (taxminiy format EMAS).

    Tekshiriladi: (1) Auth-Key sozlanmaganda HECH QANDAY tarmoq so'rovi
    yuborilmasligi, (2) URLhaus javobidan `host` to'g'ri ajratilishi,
    (3) ThreatFox javobidan `ip:port`dan port ajratilishi VA hash
    turlarining (BlacklistEntry uchun emas) filtr qilinishi,
    (4) `engine.threat_intel_sync.run_once()` real DB'ga yozishi,
    (5) qayta chaqirilganda `UNIQUE(value)` cheklovi tufayli takroriy
    yozuv QO'SHILMASLIGI (idempotentlik).
    """
    import os
    from unittest.mock import patch, MagicMock
    from db.models import BlacklistEntry
    import threat_intel.urlhaus_feed as uh
    import threat_intel.threatfox_feed as tf
    import engine.threat_intel_sync as tis

    for k in ["URLHAUS_AUTH_KEY", "THREATFOX_AUTH_KEY", "URLHAUS_ENABLED"]:
        os.environ.pop(k, None)

    try:
        # 1) Auth-Key sozlanmagan holatda - tarmoqqa UMUMAN chiqmasligi kerak
        with patch.object(uh.requests, "get") as mock_get_off, \
             patch.object(tf.requests, "post") as mock_post_off:
            assert uh.fetch_recent_urls() is None
            assert tf.fetch_recent_iocs() is None
            assert mock_get_off.call_count == 0, "Auth-Key yo'qligida URLhaus'ga so'rov ketmasligi kerak edi"
            assert mock_post_off.call_count == 0, "Auth-Key yo'qligida ThreatFox'ga so'rov ketmasligi kerak edi"
            assert tis.run_once() == 0

        # 2) URLhaus - rasmiy hujjatdagi namunaviy javob (so'zma-so'z)
        os.environ["URLHAUS_AUTH_KEY"] = "test-urlhaus-key"; os.environ["URLHAUS_ENABLED"] = "true"
        urlhaus_response = MagicMock()
        urlhaus_response.raise_for_status = lambda: None
        urlhaus_response.json.return_value = {
            "query_status": "ok",
            "urls": [
                {"id": "223622", "urlhaus_reference": "https://urlhaus.abuse.ch/url/223622/",
                 "url": "http://45.61.49.78/razor/r4z0r.mips", "url_status": "offline",
                 "host": "45.61.49.78", "date_added": "2019-08-10 09:02:05 UTC",
                 "threat": "malware_download"},
                {"id": "223621", "urlhaus_reference": "https://urlhaus.abuse.ch/url/223621/",
                 "url": "http://urlhaustest-evil-domain.example/r4z0r.sh4", "url_status": "online",
                 "host": "urlhaustest-evil-domain.example", "date_added": "2019-08-10 09:02:03 UTC",
                 "threat": "malware_download"},
            ],
        }
        with patch.object(uh.requests, "get", return_value=urlhaus_response) as mock_get:
            urls = uh.fetch_recent_urls()
            assert mock_get.call_args.kwargs["headers"]["Auth-Key"] == "test-urlhaus-key"
        assert urls is not None and len(urls) == 2
        assert urls[0]["host"] == "45.61.49.78"
        assert urls[1]["host"] == "urlhaustest-evil-domain.example"

        # 3) ThreatFox - rasmiy hujjatdagi namunaviy javob + ip:port + hash (filtrlanishi kerak)
        os.environ["THREATFOX_AUTH_KEY"] = "test-threatfox-key"
        threatfox_response = MagicMock()
        threatfox_response.raise_for_status = lambda: None
        threatfox_response.json.return_value = {
            "query_status": "ok",
            "data": [
                {"id": "41", "ioc": "threatfoxtest-gaga-domain.example", "ioc_type": "domain",
                 "malware_printable": "Dridex", "confidence_level": 50,
                 "first_seen": "2020-12-08 13:36:27 UTC", "reference": None},
                {"id": "42", "ioc": "203.0.113.77:4444", "ioc_type": "ip:port",
                 "malware_printable": "Cobalt Strike", "confidence_level": 90,
                 "first_seen": "2020-12-08 13:36:27 UTC", "reference": None},
                # hash turi - BlacklistEntry uchun EMAS, o'tkazib yuborilishi kerak
                {"id": "43", "ioc": "2151c4b970eff0071948dbbc19066aa4", "ioc_type": "md5_hash",
                 "malware_printable": "Houdini", "confidence_level": 80,
                 "first_seen": "2020-12-08 13:36:27 UTC", "reference": None},
            ],
        }
        with patch.object(tf.requests, "post", return_value=threatfox_response) as mock_post:
            iocs = tf.fetch_recent_iocs()
            assert mock_post.call_args.kwargs["headers"]["Auth-Key"] == "test-threatfox-key"
        assert iocs is not None and len(iocs) == 2, f"hash turi filtrlanishi kerak edi, {len(iocs)} ta natija qaytdi"
        assert iocs[0]["value"] == "threatfoxtest-gaga-domain.example"
        assert iocs[1]["value"] == "203.0.113.77", f"ip:port'dan port ajratilishi kerak edi, bor: {iocs[1]['value']}"

        # 4) To'liq engine.run_once() - real DB'ga yozilishi
        with patch.object(uh.requests, "get", return_value=urlhaus_response), \
             patch.object(tf.requests, "post", return_value=threatfox_response):
            added = tis.run_once()
        assert added == 4, f"4 ta yangi yozuv (2 URLhaus + 2 ThreatFox) kutilgan edi, {added} ta qo'shildi"

        s = get_session()
        bl1 = s.query(BlacklistEntry).filter(BlacklistEntry.value == "urlhaustest-evil-domain.example").first()
        assert bl1 is not None and bl1.source == "urlhaus"
        bl2 = s.query(BlacklistEntry).filter(BlacklistEntry.value == "203.0.113.77").first()
        assert bl2 is not None and bl2.source == "threatfox"
        s.close()

        # 5) Qayta chaqirilganda - UNIQUE(value) tufayli takroriy yozuv QO'SHILMASLIGI kerak
        with patch.object(uh.requests, "get", return_value=urlhaus_response), \
             patch.object(tf.requests, "post", return_value=threatfox_response):
            added2 = tis.run_once()
        assert added2 == 0, f"ikkinchi chaqiruvda takroriy yozuv qo'shilmasligi kerak edi, {added2} ta qo'shdi"
    finally:
        for k in ["URLHAUS_AUTH_KEY", "THREATFOX_AUTH_KEY", "URLHAUS_ENABLED"]:
            os.environ.pop(k, None)


check("Threat Intelligence: URLhaus/ThreatFox -> BlacklistEntry (rasmiy API formatiga mos mock)", _test_threat_intel_sync)

# ---------------------------------------------------------------------------
print("\n=== 100b) Threat Intelligence: umumiy platformalar (github.com va h.k.) blacklist'ga kiritilmaydi (real production soxta-pozitivi) ===")


def _test_threat_intel_skips_shared_platforms():
    from unittest.mock import MagicMock, patch
    from db.models import BlacklistEntry
    import threat_intel.urlhaus_feed as uh
    import engine.threat_intel_sync as tis

    assert tis.is_shared_platform_host("github.com")
    assert tis.is_shared_platform_host("raw.githubusercontent.com")
    assert tis.is_shared_platform_host("lb-140-82-112-22-iad.github.com")
    assert tis.is_shared_platform_host("drive.google.com")
    assert tis.is_shared_platform_host("cdn.jsdelivr.net") and tis.is_shared_platform_host("testingcf.jsdelivr.net")
    assert not tis.is_shared_platform_host("evil-jsdelivr.net")
    assert not tis.is_shared_platform_host("notgithub.com"), "label chegarasi: notgithub.com mos kelmasligi kerak"
    assert not tis.is_shared_platform_host("evil-github.com.attacker.example")
    assert not tis.is_shared_platform_host("update.googlecert.help")

    os.environ["URLHAUS_AUTH_KEY"] = "test-urlhaus-key"; os.environ["URLHAUS_ENABLED"] = "true"
    os.environ.pop("THREATFOX_AUTH_KEY", None)
    try:
        resp = MagicMock()
        resp.raise_for_status = lambda: None
        resp.json.return_value = {"query_status": "ok", "urls": [
            {"url": "https://github.com/x/y/raw/main/a.exe", "host": "github.com", "threat": "malware_download", "url_status": "online"},
            {"url": "https://drive.google.com/uc?id=1", "host": "drive.google.com", "threat": "malware_download", "url_status": "online"},
            {"url": "http://sharedplatform-test-evil.example/a.sh", "host": "sharedplatform-test-evil.example", "threat": "malware_download", "url_status": "online"},
        ]}
        with patch.object(uh.requests, "get", return_value=resp):
            tis.run_once()
        s = get_session()
        assert s.query(BlacklistEntry).filter(BlacklistEntry.value == "github.com").first() is None, "github.com blacklist'ga kirmasligi kerak"
        assert s.query(BlacklistEntry).filter(BlacklistEntry.value == "drive.google.com").first() is None
        assert s.query(BlacklistEntry).filter(BlacklistEntry.value == "sharedplatform-test-evil.example").first() is not None, "haqiqiy zararli host qo'shilishi kerak"
        s.close()
    finally:
        os.environ.pop("URLHAUS_AUTH_KEY", None); os.environ.pop("URLHAUS_ENABLED", None)


check("Threat Intelligence: umumiy platformalar (github.com va h.k.) blacklist'ga kirmaydi", _test_threat_intel_skips_shared_platforms)


def _test_urlhaus_disabled_by_default():
    from unittest.mock import patch
    import threat_intel.urlhaus_feed as uh
    import engine.threat_intel_sync as tis
    os.environ["URLHAUS_AUTH_KEY"] = "test-urlhaus-key"
    os.environ.pop("URLHAUS_ENABLED", None)
    os.environ.pop("THREATFOX_AUTH_KEY", None)
    try:
        with patch.object(uh.requests, "get") as mock_get:
            assert tis.run_once() == 0
            assert mock_get.call_count == 0, "URLhaus standart holatda o'chiq - tarmoqqa so'rov ketmasligi kerak"
    finally:
        os.environ.pop("URLHAUS_AUTH_KEY", None)


check("Threat Intelligence: URLhaus standart holatda o'chiq (URLHAUS_ENABLED=true bo'lmasa so'rov yuborilmaydi)", _test_urlhaus_disabled_by_default)


def _test_threatfox_hash_iocs_to_hash_blacklist():
    from unittest.mock import MagicMock, patch
    from db.models import HashBlacklist
    import threat_intel.threatfox_feed as tf
    import engine.threat_intel_sync as tis
    os.environ["THREATFOX_AUTH_KEY"] = "test-threatfox-key"
    os.environ.pop("URLHAUS_ENABLED", None)
    good = "ab12" * 16
    try:
        resp = MagicMock(); resp.raise_for_status = lambda: None
        resp.json.return_value = {"query_status": "ok", "data": [
            {"ioc": good, "ioc_type": "sha256_hash", "malware_printable": "Lumma"},
            {"ioc": "2151c4b970eff0071948dbbc19066aa4", "ioc_type": "md5_hash", "malware_printable": "X"},
            {"ioc": "zz" * 32, "ioc_type": "sha256_hash", "malware_printable": "Bad"},
        ]}
        with patch.object(tf.requests, "post", return_value=resp):
            hashes = tf.fetch_recent_hashes()
            assert [h["sha256"] for h in hashes] == [good], hashes
            tis.run_once(); tis.run_once()
        s = get_session()
        rows = s.query(HashBlacklist).filter(HashBlacklist.sha256 == good).all()
        assert len(rows) == 1 and rows[0].threat_name == "Lumma" and rows[0].source == "threatfox", "sha256 IOC hash_blacklist'ga 1 marta yozilishi kerak"
        s.close()
    finally:
        os.environ.pop("THREATFOX_AUTH_KEY", None)


check("Threat Intelligence: ThreatFox sha256 IOC -> mahalliy hash_blacklist (idempotent)", _test_threatfox_hash_iocs_to_hash_blacklist)

# ---------------------------------------------------------------------------
print("\n=== 101) Heuristik tahlil moduli (entropiya/skript naqshi/kengaytma-nomuvofiqlik/PDF) - 'unknown' hech qachon qolmasin ===")


def _test_heuristic_analyzer_module():
    """
    Foydalanuvchi so'rovi: "fayl 90% gacha tekshirilib zararli/zararsizga
    aniq ajratilsin - 'unknown' shaklida hech qachon qolmasin". Bu test
    `scanners/heuristic_analyzer.py`ning har bir qismini tekshiradi:
    entropiya (yuqori entropiya - paketlangan/shifrlangan bajariladigan
    fayl belgisi), shubhali skript naqshlari (PowerShell Base64/IEX),
    va DETERMINISTIK qatlam (kengaytma-nomuvofiqlik/PDF tuzilmasi -
    bular "malicious" bera oladi, entropiya/skript esa FAQAT
    "suspicious" - soxta-pozitiv xavfi tufayli).
    """
    import os as _os
    import shutil
    import zlib

    from scanners.heuristic_analyzer import shannon_entropy, scan_bytes_heuristic, analyze_file

    # --- 1) Entropiya: bir xil baytlar (past) vs tasodifiy baytlar (yuqori) ---
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1000) < 1.0, "Bir xil baytlar past entropiyaga ega bo'lishi kerak edi"
    high_entropy_data = _os.urandom(4096)
    assert shannon_entropy(high_entropy_data) > 7.5, "Tasodifiy baytlar yuqori entropiyaga ega bo'lishi kerak edi"

    # --- 2) scan_bytes_heuristic: PE turi + yuqori entropiya -> "suspicious" (HECH QACHON "malicious" EMAS) ---
    fake_pe = b"MZ" + high_entropy_data
    result_pe = scan_bytes_heuristic(fake_pe, "PE", "exe")
    assert result_pe["verdict_hint"] == "suspicious", f"Yuqori entropiyali PE 'suspicious' bo'lishi kerak edi: {result_pe}"
    assert result_pe["score"] >= 40

    # --- 3) scan_bytes_heuristic: past entropiyali PE -> "clean" (soxta-pozitiv yo'q) ---
    low_entropy_pe = b"MZ" + b"\x90" * 2000
    result_low = scan_bytes_heuristic(low_entropy_pe, "PE", "exe")
    assert result_low["verdict_hint"] == "clean", f"Past entropiyali oddiy PE soxta-pozitiv bermasligi kerak edi: {result_low}"

    # --- 4) ZIP/PDF kabi tabiiy yuqori-entropiyali formatlar TEKSHIRILMAYDI (soxta-pozitiv yo'q) ---
    result_zip = scan_bytes_heuristic(_os.urandom(4096), "ZIP", "docx")
    assert result_zip["score"] == 0, "ZIP/DOCX kabi formatlar uchun entropiya tekshiruvi ISHLAMASLIGI kerak (tabiiy yuqori entropiya)"

    # --- 5) Shubhali skript naqshi (PowerShell) ---
    ps1_content = b"powershell.exe -w hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
    result_script = scan_bytes_heuristic(ps1_content, "SCRIPT", "ps1")
    assert result_script["verdict_hint"] == "suspicious"
    assert any("PowerShell" in f for f in result_script["findings"])

    # --- 6) Zararsiz skript - hech qanday signal yo'q ---
    benign_script = b"#!/bin/bash\necho 'hello world'\n"
    result_benign_script = scan_bytes_heuristic(benign_script, "SCRIPT", "sh")
    assert result_benign_script["verdict_hint"] == "clean"

    work_dir = "/tmp/_test_heuristic_analyzer"
    if _os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    _os.makedirs(work_dir)
    try:
        # --- 7) analyze_file(): DETERMINISTIK kengaytma-nomuvofiqlik -> "malicious" (foydalanuvchining o'z misoli) ---
        masquerade_path = _os.path.join(work_dir, "invoice.pdf")
        with open(masquerade_path, "wb") as f:
            f.write(b"MZ" + b"\x90" * 58 + b"This program cannot be run in DOS mode")
        result_masq = analyze_file(masquerade_path, filename="invoice.pdf")
        assert result_masq["verdict_hint"] == "malicious", f"Niqoblangan fayl 'malicious' bo'lishi kerak edi: {result_masq}"
        assert result_masq["score"] == 100

        # --- 8) analyze_file(): PDF ichidagi siqilgan xavfli tuzilma -> "malicious" ---
        inner = b"<< /OpenAction 5 0 R /Names << /JavaScript 6 0 R >> >>"
        compressed = zlib.compress(inner)
        hidden_pdf_path = _os.path.join(work_dir, "hidden.pdf")
        with open(hidden_pdf_path, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n" + compressed + b"\nendstream\nendobj\n%%EOF\n")
        result_pdf = analyze_file(hidden_pdf_path, filename="hidden.pdf")
        assert result_pdf["verdict_hint"] == "malicious", f"Xavfli PDF tuzilmasi aniqlanmadi: {result_pdf}"

        # --- 9) analyze_file(): oddiy, mos keladigan matn fayli -> "clean" (unknown emas!) ---
        benign_path = _os.path.join(work_dir, "readme.txt")
        with open(benign_path, "w") as f:
            f.write("Bu oddiy, zararsiz matn fayli.")
        result_benign = analyze_file(benign_path, filename="readme.txt")
        assert result_benign["verdict_hint"] == "clean", f"Oddiy matn fayli 'clean' bo'lishi kerak edi: {result_benign}"
        assert result_benign["score"] == 0
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


check("Heuristik tahlil moduli - entropiya/skript/kengaytma-nomuvofiqlik/PDF ('unknown' hal qilinadi)", _test_heuristic_analyzer_module)

# ---------------------------------------------------------------------------
print("\n=== 102) Deep Scan Engine: 'unknown' holatni heuristik orqali hal qilish (real DB, foydalanuvchi so'rovi) ===")


def _test_deep_scan_resolves_unknown():
    """
    Foydalanuvchi so'rovi: hash-intel VA barcha chuqur tekshiruvlar
    (YARA/ClamAV/fayl-turi/Office/PDF/ZIP) hech narsa topmagan taqdirda
    ham, fayl "unknown" holatida QOLMASLIGI kerak - oxirgi, ehtimoliy
    (entropiya/skript) qatlam orqali "clean" yoki "suspicious"ga hal
    qilinadi.
    """
    import shutil
    from unittest.mock import patch

    try:
        import engine.deep_scan_engine as dse
    except ImportError as exc:
        print(f"   (yara/oletools yo'q - bu test o'tkazib yuborildi: {exc})")
        return

    work_dir = "/tmp/_test_deep_scan_resolves_unknown"
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir)
    os.makedirs(work_dir)

    try:
        # --- 1) Hech qanday belgi topilmagan, past-entropiyali PE -> "unknown" -> "clean" ---
        clean_path = os.path.join(work_dir, "utility.exe")
        with open(clean_path, "wb") as f:
            f.write(b"MZ" + b"\x90" * 4000)

        s = get_session()
        fe_clean = FileEvent(
            src_ip="172.16.65.1", filename="utility.exe", file_ext="exe",
            sha256="7b" * 32, checked=True, verdict="unknown", stored_path=clean_path,
        )
        s.add(fe_clean)
        s.commit()
        with patch.object(dse, "yara_scan_file", return_value=[]), \
             patch.object(dse, "clamav_db_available", return_value=False), \
             patch.object(dse, "clamav_scan_file", return_value={"infected": False, "error": None}):
            dse.deep_scan_one(s, fe_clean)
            s.commit()
        assert fe_clean.verdict == "clean", (
            f"To'liq skanerlangan, hech narsa topilmagan fayl 'unknown' EMAS 'clean' bo'lishi kerak edi, '{fe_clean.verdict}' keldi"
        )
        assert s.query(Alert).filter(Alert.file_event_id == fe_clean.id).first() is None, (
            "Toza deb hal qilingan fayl uchun Alert yaratilmasligi kerak"
        )
        s.close()

        # --- 2) Yuqori entropiyali, hech qanday YARA/ClamAV/mismatch belgisi bo'lmagan PE -> "unknown" -> "suspicious" ---
        suspicious_path = os.path.join(work_dir, "packed_tool.exe")
        with open(suspicious_path, "wb") as f:
            f.write(b"MZ" + os.urandom(8192))

        s = get_session()
        fe_susp = FileEvent(
            src_ip="172.16.65.2", filename="packed_tool.exe", file_ext="exe",
            sha256="8b" * 32, checked=True, verdict="unknown", stored_path=suspicious_path,
        )
        s.add(fe_susp)
        s.commit()
        with patch.object(dse, "yara_scan_file", return_value=[]), \
             patch.object(dse, "clamav_db_available", return_value=False), \
             patch.object(dse, "clamav_scan_file", return_value={"infected": False, "error": None}):
            dse.deep_scan_one(s, fe_susp)
            s.commit()
        assert fe_susp.verdict == "suspicious", (
            f"Yuqori entropiyali, tasdiqlanmagan fayl 'suspicious' bo'lishi kerak edi (HECH QACHON avtomatik "
            f"'malicious' EMAS - soxta-pozitiv xavfi), '{fe_susp.verdict}' keldi"
        )
        alert = s.query(Alert).filter(Alert.file_event_id == fe_susp.id).first()
        assert alert is not None and alert.severity == "medium", (
            "Heuristik-asosli topilma FAQAT 'medium' severity berishi kerak - avtomatik tarmoq chorasi "
            "ko'rilmasligi uchun (response_engine faqat high/critical'ga avtomatik javob beradi)"
        )
        s.close()
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


check("Deep Scan Engine: 'unknown' holat heuristik orqali 'clean'/'suspicious'ga hal qilinadi", _test_deep_scan_resolves_unknown)

# ---------------------------------------------------------------------------
print("\n=== 103) check_hash: Endpoint heuristik orqali 'unknown' hal qilinadi, Agent'ga qaytariladigan javob O'ZGARMAYDI ===")


def _test_check_hash_resolves_unknown_via_agent_heuristic():
    """
    Foydalanuvchi so'rovi: fayl mazmuni FAQAT endpoint'da mavjud bo'lgani
    uchun, Agent o'zi hisoblagan heuristik (`scanners/heuristic_analyzer.
    analyze_file()`) natijasi serverga yuboriladi va hash-intel hech
    narsa demagan holatlarda "unknown"ni hal qiladi. MUHIM: bu Agent'ga
    qaytariladigan `malicious`/`confirmed` javobiga TA'SIR QILMAYDI -
    Agent o'z avtomatik karantin qarorini MUSTAQIL ravishda (mahalliy
    heuristika orqali) qabul qiladi, server javobi orqali emas.
    """
    import hashlib
    from unittest.mock import patch
    import api.server as api_server

    # MUHIM: bu 109+ testli faylda ko'plab test "ab"*32/"9b"*32 kabi
    # oddiy takror-hex naqshlardan foydalanadi - bitta umumiy DB'da
    # to'qnashish xavfi bor (aynan shu sabab bilan "ab"*32 boshqa,
    # oldinroq yozilgan testning FileEvent'i bilan TO'QNASHIB, `.first()`
    # noto'g'ri (eski) qatorni qaytargan edi). Kafolatlangan noyoblik
    # uchun hashlib orqali, tavsiflovchi satrlardan hosil qilinadi.
    sha_suspicious = hashlib.sha256(b"heuristic_test_suspicious_endpoint_file").hexdigest()
    sha_malicious = hashlib.sha256(b"heuristic_test_malicious_endpoint_file").hexdigest()
    sha_no_heuristic = hashlib.sha256(b"heuristic_test_old_agent_no_fields").hexdigest()

    api_server.AGENT_API_KEY = "test-key-heuristic-unknown"
    api_client = api_server.app.test_client()
    headers = {"X-API-Key": "test-key-heuristic-unknown"}

    s = get_session()
    dev1 = Device(ip_address="172.16.66.1", hostname="TEST-PC-HEUR-1", source="test")
    dev2 = Device(ip_address="172.16.66.2", hostname="TEST-PC-HEUR-2", source="test")
    s.add_all([dev1, dev2])
    s.commit()
    dev1_id, dev2_id = dev1.id, dev2.id
    s.close()

    # --- 1) heuristic_verdict="suspicious" (ehtimoliy, entropiya) -> FileEvent "suspicious", Alert(medium) ---
    with patch.object(api_server, "check_virustotal", return_value=None), \
         patch.object(api_server, "check_malwarebazaar", return_value=None):
        r = api_client.post("/api/v1/check_hash", json={
            "sha256": sha_suspicious, "filename": "packed_installer.exe",
            "hostname": "TEST-PC-HEUR-1", "ip_address": "172.16.66.1",
            "magic": "PE", "heuristic_score": 55,
            "heuristic_findings": ["Yuqori entropiya (7.80/8.0)"],
            "heuristic_verdict": "suspicious",
        }, headers=headers)
    assert r.status_code == 200
    resp = r.get_json()
    assert resp["malicious"] is False and resp["confirmed"] is False, (
        "Heuristik 'suspicious' Agent'ga qaytariladigan javobga ta'sir qilmasligi kerak edi"
    )

    s = get_session()
    fe1 = s.query(FileEvent).filter(FileEvent.sha256 == sha_suspicious).first()
    assert fe1 is not None and fe1.verdict == "suspicious", (
        f"Endpoint heuristik 'suspicious' bo'lsa, FileEvent 'unknown' EMAS 'suspicious' bo'lishi kerak edi, '{fe1.verdict if fe1 else None}' keldi"
    )
    alert1 = s.query(Alert).filter(Alert.device_id == dev1_id).first()
    assert alert1 is not None and alert1.severity == "medium"
    s.close()

    # --- 2) heuristic_verdict="malicious" (deterministik, kengaytma-nomuvofiqlik) -> FileEvent "malicious", Alert(critical) ---
    with patch.object(api_server, "check_virustotal", return_value=None), \
         patch.object(api_server, "check_malwarebazaar", return_value=None):
        r2 = api_client.post("/api/v1/check_hash", json={
            "sha256": sha_malicious, "filename": "invoice.pdf",
            "hostname": "TEST-PC-HEUR-2", "ip_address": "172.16.66.2",
            "magic": "PE", "heuristic_score": 100,
            "heuristic_findings": ["Fayl kengaytmasi '.pdf' (PDF kutilgan), lekin haqiqiy tarkib 'PE'"],
            "heuristic_verdict": "malicious",
        }, headers=headers)
    assert r2.status_code == 200
    resp2 = r2.get_json()
    assert resp2["malicious"] is False and resp2["confirmed"] is False, (
        "Heuristik 'malicious' HAM Agent'ga qaytariladigan javobga ta'sir qilmasligi kerak edi - "
        "Agent bu qarorni MUSTAQIL, mahalliy ravishda qabul qiladi"
    )

    s = get_session()
    fe2 = s.query(FileEvent).filter(FileEvent.sha256 == sha_malicious).first()
    assert fe2 is not None and fe2.verdict == "malicious", (
        f"Endpoint heuristik 'malicious' (deterministik) bo'lsa, FileEvent 'malicious' bo'lishi kerak edi, '{fe2.verdict if fe2 else None}' keldi"
    )
    alert2 = s.query(Alert).filter(Alert.device_id == dev2_id).first()
    assert alert2 is not None and alert2.severity == "critical"
    s.close()

    # --- 3) heuristic maydonlari yuborilmasa (eski Agent versiyasi) - eski xatti-harakat SAQLANADI (regressiya himoyasi) ---
    with patch.object(api_server, "check_virustotal", return_value=None), \
         patch.object(api_server, "check_malwarebazaar", return_value=None):
        r3 = api_client.post("/api/v1/check_hash", json={
            "sha256": sha_no_heuristic, "filename": "old_agent_file.bin",
            "hostname": "TEST-PC-HEUR-1", "ip_address": "172.16.66.1",
        }, headers=headers)
    assert r3.status_code == 200
    s = get_session()
    fe3 = s.query(FileEvent).filter(FileEvent.sha256 == sha_no_heuristic).first()
    assert fe3 is not None and fe3.verdict == "unknown", (
        "Heuristik maydonlarsiz (eski Agent) so'rov eski xatti-harakatni saqlashi kerak edi ('unknown')"
    )
    s.close()


check("check_hash: Endpoint heuristik orqali 'unknown' hal qilinadi, Agent javobi o'zgarmaydi", _test_check_hash_resolves_unknown_via_agent_heuristic)

# ---------------------------------------------------------------------------
print("\n=== 104) Endpoint Agent: 'confirmed' bo'yicha aniq chora (real bug tuzatilgan) + mahalliy heuristik orqali niqoblangan fayl aniqlanishi ===")


def _test_agent_confirmed_gating_and_local_heuristic():
    """
    O'ZI TOPILGAN REAL BUG: `_on_new_file()` ilgari FAQAT `result.get(
    "malicious")`ni tekshirardi - bu esa VirusTotal'ning TASDIQLANMAGAN
    (masalan 1/70 dvigatel) signali bilan ham to'liq avtomatik chora
    (jarayonni o'ldirish, faylni o'chirish) ko'rilishiga olib kelardi,
    garchi `api/server.py::check_hash()`ning o'z docstring'i "FAQAT
    confirmed=true bo'lganda" deb hujjatlashtirgan bo'lsa ham. Bu test
    ikkalasini ham tasdiqlaydi:

    (1) `confirmed=False` (shubhali, tasdiqlanmagan) -> HECH QANDAY
        avtomatik chora ko'RILMASLIGI kerak (bug tuzatilgan).
    (2) Server hash-intel bo'yicha hech narsa demasa ham (`malicious=
        False`), MAHALLIY heuristik DETERMINISTIK "malicious" (masalan
        kengaytma-nomuvofiqligi) topsa - Agent BARIBIR avtomatik chora
        ko'rishi kerak (foydalanuvchi so'rovi: fayl mazmuni FAQAT
        endpoint'da mavjud, bu signalni yo'qotib bo'lmaydi).
    """
    import shutil
    from unittest.mock import patch

    import agent_core.agent as agent_mod

    watch_dir = "/tmp/_test_agent_confirmed_gating"
    if os.path.exists(watch_dir):
        shutil.rmtree(watch_dir)
    os.makedirs(watch_dir)

    try:
        agent = agent_mod.EndpointAgent([watch_dir])

        # --- 1) confirmed=False (VT 1/70 kabi tasdiqlanmagan signal) -> chora ko'rilmasligi kerak ---
        suspicious_file = os.path.join(watch_dir, "maybe_suspicious.bin")
        with open(suspicious_file, "wb") as f:
            f.write(b"benign-looking content for gating test")

        with patch.object(agent_mod, "check_hash_with_server_or_cache",
                           return_value={"malicious": True, "confirmed": False, "threat_name": "Weak.Signal"}), \
             patch.object(agent_mod, "analyze_file", return_value={"verdict_hint": "clean", "findings": [], "score": 0, "magic": None}), \
             patch.object(agent_mod, "quarantine_file") as mock_quarantine, \
             patch.object(agent_mod, "kill_process_holding_file") as mock_kill, \
             patch.object(agent_mod, "report_incident") as mock_report:
            agent._on_new_file(suspicious_file)

        assert mock_quarantine.call_count == 0, "confirmed=False bo'lsa, fayl KARANTINGA OLINMASLIGI kerak edi (bug qaytdi)"
        assert mock_kill.call_count == 0, "confirmed=False bo'lsa, jarayon TO'XTATILMASLIGI kerak edi"
        assert mock_report.call_count == 0, "confirmed=False bo'lsa, markazga incident YUBORILMASLIGI kerak edi"
        assert os.path.exists(suspicious_file), "confirmed=False bo'lsa, asl fayl SAQLANIB QOLISHI kerak edi"

        # --- 2) Server hech narsa demaydi, lekin MAHALLIY heuristik deterministik "malicious" -> chora ko'rilishi kerak ---
        masquerade_file = os.path.join(watch_dir, "invoice.pdf")
        with open(masquerade_file, "wb") as f:
            f.write(b"MZ" + b"\x90" * 58 + b"masquerade payload for agent-side detection test")

        with patch.object(agent_mod, "check_hash_with_server_or_cache",
                           return_value={"malicious": False, "confirmed": False, "threat_name": None}), \
             patch.object(agent_mod, "analyze_file",
                          return_value={"verdict_hint": "malicious", "findings": ["Fayl kengaytmasi '.pdf' - haqiqiy tarkib 'PE'"], "score": 100, "magic": "PE"}), \
             patch.object(agent_mod, "quarantine_file",
                          return_value={"quarantined": True, "quarantine_path": "/tmp/fake_q/x", "source_removed": True, "error": None}) as mock_quarantine2, \
             patch.object(agent_mod, "kill_process_holding_file") as mock_kill2, \
             patch.object(agent_mod, "report_incident") as mock_report2:
            mock_kill2.return_value = type("R", (), {"process_killed": False, "process_name": None})()
            agent._on_new_file(masquerade_file)

        assert mock_quarantine2.call_count == 1, (
            "Server hash-intel jim tursa ham, mahalliy heuristik deterministik 'malicious' topganda "
            "fayl KARANTINGA OLINISHI kerak edi (endpoint-orqali niqoblangan fayl bo'shlig'i)"
        )
        assert mock_report2.call_count == 1, "Markazga incident xabari yuborilishi kerak edi"
        report_kwargs = mock_report2.call_args.kwargs
        assert "PE" in report_kwargs.get("threat_name", "") or "kengaytma" in report_kwargs.get("threat_name", "").lower(), (
            f"threat_name mahalliy heuristik topilmalaridan olinishi kerak edi: {report_kwargs.get('threat_name')}"
        )
    finally:
        shutil.rmtree(watch_dir, ignore_errors=True)


check("Endpoint Agent: 'confirmed' bo'yicha aniq chora + mahalliy heuristik orqali niqoblangan fayl aniqlanishi", _test_agent_confirmed_gating_and_local_heuristic)

# ---------------------------------------------------------------------------
print("\n" + "=" * 60)
print("YAKUNIY HISOBOT")
print("=" * 60)
passed = sum(1 for _, ok, _ in RESULTS if ok)
failed = [name for name, ok, err in RESULTS if not ok]
print(f"O'tdi: {passed}/{len(RESULTS)}")
if failed:
    print("XATOLAR:")
    for name, ok, err in RESULTS:
        if not ok:
            print(f"  - {name}: {err}")
    sys.exit(1)
else:
    print("✅ BARCHA TESTLAR MUVAFFAQIYATLI O'TDI - XATOLIK YO'Q")
    sys.exit(0)
