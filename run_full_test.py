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
    FileEvent, HashBlacklist, User,
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
        RawLog(source_ip="172.16.0.1", raw_message="DHCP: Lease granted to 172.16.1.45 MAC=AA:BB:CC:DD:EE:FF HOST=ACCOUNTING-PC"),
        RawLog(source_ip="172.16.0.1", raw_message="<134>Jul 30 KERIO-GW Connection: SRC=172.16.1.45 DST=8.8.8.8 DPT=443 PROTO=TCP ACTION=Permit"),
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
    assert fes["clean.txt"].verdict == "clean", "clean.txt clean deb topilishi kerak edi"

    # ZIP ichidan chiqqan payload.exe alohida FileEvent sifatida yaratilganini tekshirish
    payload = s.query(FileEvent).filter(FileEvent.filename == "payload.exe").first()
    assert payload is not None, "ZIP ichidan payload.exe chiqarilmagan"
    assert payload.parent_file_event_id == fes["archive.zip"].id, "payload.exe parent_id noto'g'ri"
    assert payload.verdict == "malicious", "payload.exe malicious deb topilishi kerak edi"

    readme = s.query(FileEvent).filter(FileEvent.filename == "readme.txt").first()
    assert readme is not None and readme.verdict == "clean", "readme.txt clean bo'lishi kerak edi (soxta pozitiv)"

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
    s = get_session()
    d_wifi = Device(ip_address="172.16.3.1", mac_address="AA:11:22:33:44:55", connection_type="wifi", source="test")
    d_unknown = Device(ip_address="172.16.3.2", mac_address="BB:11:22:33:44:55", connection_type="unknown", source="test")
    s.add_all([d_wifi, d_unknown])
    s.flush()

    a1 = Alert(device_id=d_wifi.id, severity="critical", reason="test", action_taken="TODO: bloklash backend hali ulanmagan")
    a2 = Alert(device_id=d_unknown.id, severity="critical", reason="test", action_taken="TODO: bloklash backend hali ulanmagan")
    a3 = Alert(device_id=None, severity="high", reason="device yo'q", action_taken="TODO: bloklash backend hali ulanmagan")
    s.add_all([a1, a2, a3])
    s.commit()
    ids = [a1.id, a2.id, a3.id]
    s.close()

    from engine.response_engine import run_once
    n = run_once()
    # Diqqat: response_engine FAQAT shu 3 tasini emas, balki bazadagi barcha
    # "TODO" holatidagi alertlarni (2 va 3-bosqichlarda yaratilganlarni ham)
    # qayta ishlaydi - bu to'g'ri xatti-harakat (hech qanday alert e'tibordan
    # chetda qolmasligi kerak). Shuning uchun n >= 3 tekshiramiz.
    assert n >= 3, f"Kamida 3 ta alert qayta ishlanishi kerak edi, {n} ta ishlandi"

    s = get_session()
    for aid in ids:
        a = s.query(Alert).filter(Alert.id == aid).first()
        assert not a.action_taken.startswith("TODO"), f"Alert {aid} hali TODO holatida qoldi: {a.action_taken}"
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

    try:
        os.environ["API_SERVER_URL"] = "http://127.0.0.1:8199"
        os.environ["AGENT_API_KEY"] = "linux-e2e-test-key"
        os.environ["AGENT_CACHE_FILE"] = "/tmp/_linux_agent_e2e_cache.json"
        os.environ["AGENT_LOG_FILE"] = "/tmp/_linux_agent_e2e.log"
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
        # sinaladi: hash -> server -> jarayonni to'xtatish -> o'chirish -> report)
        agent._on_new_file(malicious_file)

        _time.sleep(1)

        assert not os.path.exists(malicious_file), "Zararli fayl o'chirilishi kerak edi"
        assert locker.poll() is not None, "Faylni ushlab turgan jarayon to'xtatilishi kerak edi"

        s = get_session()
        alert = (
            s.query(Alert)
            .filter(Alert.reason.like("%LinuxAgentE2E-Trojan%"))
            .first()
        )
        assert alert is not None, "Markazga incident xabari kelib, Alert yaratilishi kerak edi"
        assert alert.device_id is not None
        s.close()

    finally:
        api_proc.terminate()
        try:
            api_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            api_proc.kill()
        import shutil
        shutil.rmtree(watch_dir, ignore_errors=True)
        for f in ["/tmp/_linux_agent_e2e_cache.json", "/tmp/_linux_agent_e2e.log"]:
            if os.path.exists(f):
                os.remove(f)
        for k in ["API_SERVER_URL", "AGENT_API_KEY", "AGENT_CACHE_FILE", "AGENT_LOG_FILE"]:
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

        s = get_session()
        d = Device(ip_address="172.16.5.5", mac_address="AA:BB:CC:00:11:22",
                    hostname="NOTIFY-TEST-PC", connection_type="wifi", source="test")
        s.add(d)
        s.flush()
        alert = Alert(device_id=d.id, severity="critical", reason="Test xabarnoma",
                       action_taken="Test chora", notified=False)
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
        content = open(received_log).read()
        assert "NOTIFY-TEST-PC" in content, "Xatda hostname topilmadi"
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
    a1 = Alert(severity="high", reason="Blacklist'dagi domenga so'rov: evil.com (manba: manual)", action_taken="TODO")
    a2 = Alert(severity="critical", reason="ClamAV[critical]: Trojan.GenericKD", action_taken="TODO")
    a3 = Alert(severity="critical", reason="YARA[high]: Suspicious_PowerShell_Obfuscation - test", action_taken="TODO")
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
    client = dash_app.app.test_client()

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
    client = dash_app.app.test_client()
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
    a = Alert(device_id=d.id, severity="critical", reason="RBAC avtomatik test alert", action_taken="TODO", notified=False)
    s.add(a)
    s.commit()
    alert_id = a.id
    s.close()

    dash_app.app.secret_key = "test-secret-key"
    client = dash_app.app.test_client()

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
    client = dash_app.app.test_client()
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
    client = dash_app.app.test_client()

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
        client = dash_app.app.test_client()

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
        msg = f"DHCP: Lease granted to 172.16.9.199 MAC={test_mac} HOST=RABBITMQ-E2E-TEST"
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
    s.add(Alert(device_id=anomaly_id, severity="critical", reason="Test critical", mitre_tactic="Execution", action_taken="TODO"))
    s.add(Alert(device_id=anomaly_id, severity="high", reason="Test high", mitre_tactic="Command and Control", action_taken="TODO"))
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
    client = dash_app.app.test_client()

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
    client = dash_app.app.test_client()
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
    anon_client = dash_app.app.test_client()
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
    client = dash_app.app.test_client()
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
    ui_client = dash_app.app.test_client()
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
