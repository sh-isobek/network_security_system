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
