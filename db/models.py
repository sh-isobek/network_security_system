"""
Ma'lumotlar bazasi strukturasi (ORM modellar).

Jadvallar:
  - raw_logs   : kelgan har bir syslog xabarining xom nusxasi (audit uchun)
  - devices    : tarmoqdagi har bir qurilma (IP, MAC, hostname, manba)
  - events     : parsing qilingan tarmoq hodisalari (kim, qayerga, qaysi port)
  - alerts     : xavfli deb topilgan hodisalar va ko'rilgan choralar
  - whitelist  : hech qachon bloklanmaydigan IP/domenlar (masalan 1C serverlar)
  - blacklist  : ma'lum zararli IP/domenlar ro'yxati
"""
from datetime import datetime, timezone
import logging
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Text,
    ForeignKey, Boolean, Index, inspect, text
)
from sqlalchemy.orm import declarative_base, relationship

logger = logging.getLogger("db.models")

Base = declarative_base()


def utcnow() -> datetime:
    """
    datetime.utcnow() Python 3.12+ da deprecated (kelajakda olib
    tashlanadi). Buning o'rniga timezone-aware UTC vaqt olib, keyin
    tzinfo'ni tashlaymiz - natija oldingi kod bilan bir xil (naive UTC
    datetime), lekin DeprecationWarning bermaydi va SQLite bilan
    mavjud ustunlar formatiga mos keladi.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)



class RawLog(Base):
    """Har bir kelgan syslog paketining xom matni - hech narsa yo'qolmasligi uchun."""
    __tablename__ = "raw_logs"

    id = Column(Integer, primary_key=True)
    received_at = Column(DateTime, default=utcnow, nullable=False)
    source_ip = Column(String(45), nullable=False)   # syslog'ni yuborgan qurilma (Kerio/switch/UniFi)
    raw_message = Column(Text, nullable=False)
    processed = Column(Boolean, default=False)        # parser bu yozuvni qayta ishladimi

    __table_args__ = (
        Index("ix_raw_logs_processed", "processed"),
        Index("ix_raw_logs_received_at", "received_at"),
    )


class Device(Base):
    """Tarmoqda ko'rilgan har bir qurilma - IP/MAC/hostname bog'lanishi."""
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(45), nullable=False, unique=True)
    mac_address = Column(String(17))                  # keyingi bosqichda switch/UniFi'dan to'ldiriladi
    hostname = Column(String(255))
    connection_type = Column(String(20))               # "wifi" | "cable" | "unknown"
    source = Column(String(50))                         # ma'lumot qayerdan kelgani: "kerio_dhcp" | "unifi" | "switch"
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)

    # --- UEBA / Risk Score (yangi TZ 11-bo'lim) ---
    risk_score = Column(Integer, default=0)          # 0-100, engine/ueba_engine.py hisoblaydi
    risk_score_updated_at = Column(DateTime)

    # --- Asset Inventory / Network Discovery ---
    device_type = Column(String(50))                   # "server" | "switch" | "printer" | "ups" | "router" | "workstation" | "unknown"
    vendor = Column(String(255))                        # MAC OUI orqali aniqlangan ishlab chiqaruvchi
    os_guess = Column(String(255))                       # OS fingerprint yoki AD/SNMP orqali aniqlangan
    open_ports = Column(Text)                             # JSON: [{"port":22,"service":"ssh"},...]
    discovery_source = Column(String(50))                  # "arp_scan" | "icmp" | "snmp" | "ad" | "unifi" | "ruijie" | "kerio_dhcp"
    last_discovered_at = Column(DateTime)

    # --- Endpoint Agent Coverage (yangi TZ 6-bo'lim: AD orqali avtomatlashtirish) ---
    agent_last_heartbeat = Column(DateTime)                  # oxirgi marta agent "men tirikman" deb xabar bergan vaqti
    agent_version = Column(String(50))                         # agentning o'zi bildirgan versiyasi
    agent_os = Column(String(20))                                # "windows" | "linux" | "mac"

    events = relationship("Event", back_populates="device")


class Event(Base):
    """Parsing qilingan tarmoq so'rovi (kim -> qayerga -> qaysi port/protokol)."""
    __tablename__ = "events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"))
    source_ip = Column(String(45), nullable=False)
    dest_ip = Column(String(45))
    dest_domain = Column(String(255))
    dest_port = Column(Integer)
    protocol = Column(String(10))                        # HTTP / HTTPS / DNS / FTP / ...
    raw_log_id = Column(Integer, ForeignKey("raw_logs.id"))

    device = relationship("Device", back_populates="events")

    __table_args__ = (
        Index("ix_events_timestamp", "timestamp"),
        Index("ix_events_dest_ip", "dest_ip"),
    )


class Alert(Base):
    """Xavfli deb topilgan hodisa va unga nisbatan ko'rilgan chora."""
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    event_id = Column(Integer, ForeignKey("events.id"))
    file_event_id = Column(Integer, ForeignKey("file_events.id"))
    device_id = Column(Integer, ForeignKey("devices.id"))
    severity = Column(String(20))                         # low / medium / high / critical
    reason = Column(Text)                                    # nima uchun xavfli deb topildi (uzun bo'lishi mumkin - ko'p qatorli topilmalar)
    action_taken = Column(Text)                               # masalan: "IP bloklandi (firewall)"
    notified = Column(Boolean, default=False)                # admin xabar oldimi

    # --- MITRE ATT&CK belgilash ---
    mitre_technique_id = Column(String(20))                   # masalan "T1204.002"
    mitre_technique_name = Column(String(255))
    mitre_tactic = Column(String(100))                         # masalan "Execution"

    # --- RBAC: alertni tasdiqlash (faqat analyst/admin huquqi bilan) ---
    acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100))                        # username
    acknowledged_at = Column(DateTime)

    event = relationship("Event")


class WhitelistEntry(Base):
    """Hech qachon bloklanmaydigan IP/CIDR/domen (masalan 1C serverlar)."""
    __tablename__ = "whitelist"

    id = Column(Integer, primary_key=True)
    value = Column(String(255), nullable=False, unique=True)   # IP, CIDR yoki domen
    description = Column(String(255))
    added_at = Column(DateTime, default=utcnow)


class BlacklistEntry(Base):
    """Ma'lum zararli IP/domenlar ro'yxati (mahalliy yoki threat-intel'dan yuklangan)."""
    __tablename__ = "blacklist"

    id = Column(Integer, primary_key=True)
    value = Column(String(255), nullable=False, unique=True)
    source = Column(String(100))                              # "manual" | "abuse.ch" | "virustotal" ...
    reason = Column(String(255))
    added_at = Column(DateTime, default=utcnow)


class WebAccessLog(Base):
    """Qurilmaning sayt/domenlarga chiqish tarixi.

    Zeek HTTP loglari uchun to'liq URL (path bilan), HTTPS uchun esa
    TLS SNI orqali domen saqlanadi. TLS shifrlanganligi sababli HTTPS
    URL path'ini TLS decryption'siz ko'rib bo'lmaydi. DNS so'rovlari
    (Zeek dns.log yoki Windows DNS syslog orqali) ham "domen faoliyati"
    sifatida saqlanadi - bu Zeek HTTP/TLS yo'q tarmoqlarda ham asosiy
    qidiruv imkonini beradi (lekin DNS so'rovi haqiqiy sahifa
    ko'rilganini KAFOLATLAMAYDI - faqat domen so'ralganini bildiradi).
    """
    __tablename__ = "web_access_logs"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    source_ip = Column(String(45), nullable=False, index=True)
    dest_ip = Column(String(45), index=True)
    domain = Column(String(255), nullable=False, index=True)
    url = Column(String(2000))
    path = Column(String(1500))
    method = Column(String(20))
    status_code = Column(Integer)
    protocol = Column(String(20), nullable=False)
    user_agent = Column(String(1000))
    source = Column(String(30), default="zeek")

    device = relationship("Device")

    __table_args__ = (
        Index("ix_web_access_timestamp", "timestamp"),
        Index("ix_web_access_domain_timestamp", "domain", "timestamp"),
        Index("ix_web_access_source_ip_timestamp", "source_ip", "timestamp"),
    )


class FileEvent(Base):
    """Suricata (SPAN port orqali) aniqlagan har bir fayl transferi."""
    __tablename__ = "file_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    src_ip = Column(String(45), nullable=False)
    dest_ip = Column(String(45))
    filename = Column(String(500))
    file_ext = Column(String(20))
    magic = Column(String(255))                # Suricata aniqlagan fayl turi (masalan "PE32")
    size = Column(Integer)
    sha256 = Column(String(64), index=True)
    md5 = Column(String(32))
    protocol = Column(String(20))               # HTTP / SMTP / FTP
    channel = Column(String(50))                 # masalan "telegram" | "email" | "web" (URL/header asosida taxmin)
    checked = Column(Boolean, default=False)     # hash tekshiruvidan o'tdimi
    verdict = Column(String(20))                  # "clean" | "malicious" | "unknown"
    threat_score = Column(Integer, default=0)     # 0-100
    checked_sources = Column(String(255))          # qaysi manbalar tekshirildi (vergul bilan)

    # --- 4-bosqich: chuqur skanerlash (YARA / makro / PDF / arxiv) ---
    stored_path = Column(String(1000))             # Suricata file-store'dagi haqiqiy fayl yo'li (agar mavjud)
    deep_scanned = Column(Boolean, default=False)
    deep_scan_findings = Column(Text)               # topilgan shubhali belgilar (matn ko'rinishida)
    parent_file_event_id = Column(Integer, ForeignKey("file_events.id"), nullable=True)  # ZIP ichidan chiqqan fayl

    __table_args__ = (
        Index("ix_file_events_checked", "checked"),
        Index("ix_file_events_deep_scanned", "deep_scanned"),
    )


class ApiToken(Base):
    """
    API Token boshqaruvi - yangi TZ 15/20-bo'lim (API Token).

    Yagona umumiy AGENT_API_KEY'ga qo'shimcha - har bir agent/integratsiya
    uchun ALOHIDA, KUZATILADIGAN va BEKOR QILINADIGAN token. Token'ning
    o'zi hech qachon bazada saqlanmaydi - faqat uning SHA256 xesh'i
    (parollar kabi) - shuning uchun baza o'g'irlansa ham token'larning
    o'zini tiklab bo'lmaydi.
    """
    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)             # masalan "ACCOUNTING-PC agent" yoki "SIEM integratsiyasi"
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA256 xesh
    token_prefix = Column(String(12))                        # birinchi 8 belgi (UI'da ko'rsatish uchun, to'liq token emas)
    created_by = Column(String(100))
    created_at = Column(DateTime, default=utcnow)
    last_used_at = Column(DateTime)
    expires_at = Column(DateTime)                              # null = muddatsiz
    # AD/GPO orqali avtomatik ro'yxatdan o'tgan (enroll qilingan) agent
    # token'lari uchun - qaysi kompyuterga tegishli ekanligini aniq
    # bog'lash (qo'lda yaratilgan tokenlarda bo'sh qoladi).
    agent_hostname = Column(String(255), index=True)
    revoked = Column(Boolean, default=False)


class HashBlacklist(Base):
    """Ma'lum zararli fayl hash'lari (mahalliy yoki MalwareBazaar/VT'dan tasdiqlangan)."""
    __tablename__ = "hash_blacklist"

    id = Column(Integer, primary_key=True)
    sha256 = Column(String(64), nullable=False, unique=True, index=True)
    threat_name = Column(String(255))             # masalan "Trojan.GenericKD"
    source = Column(String(100))                    # "manual" | "malwarebazaar" | "virustotal"
    added_at = Column(DateTime, default=utcnow)


class DeviceHistory(Base):
    """
    Asset History - qurilma qachon birinchi topilgani, qachon
    "yo'qolgani" (uzoq vaqt ko'rinmay qolgani) haqida tarixiy log.
    Bu `devices` jadvalidagi joriy holatdan farqli - bu yerda
    O'ZGARISHLAR (event) saqlanadi, joriy holat emas.
    """
    __tablename__ = "device_history"

    id = Column(Integer, primary_key=True)
    device_ip = Column(String(45), nullable=False)
    event_type = Column(String(20), nullable=False)  # "discovered" | "disappeared" | "reappeared" | "changed"
    details = Column(Text)                              # masalan "MAC o'zgardi: X -> Y"
    timestamp = Column(DateTime, default=utcnow)

    __table_args__ = (
        Index("ix_device_history_ip", "device_ip"),
        Index("ix_device_history_timestamp", "timestamp"),
    )


class TopologyLink(Base):
    """
    Tarmoq topologiyasi bog'lanishi - LLDP/CDP orqali aniqlangan
    "qaysi qurilma qaysi switch portiga ulangan" ma'lumoti.
    """
    __tablename__ = "topology_links"

    id = Column(Integer, primary_key=True)
    local_interface = Column(String(100))                  # qaysi interfeysimizda ushlangan
    neighbor_chassis_id = Column(String(100))                # qo'shni qurilmaning ID'si (MAC yoki boshqa)
    neighbor_system_name = Column(String(255))
    neighbor_port_id = Column(String(100))
    protocol = Column(String(10))                              # "lldp" | "cdp"
    discovered_at = Column(DateTime, default=utcnow)


class DeviceBaseline(Base):
    """
    UEBA (User and Entity Behavior Analytics) - yangi TZ 11-bo'lim.

    Har bir qurilma uchun "normal xatti-harakat" statistik profili
    (baseline). MUHIM (halol tushuntirish): bu chuqur o'rganish (deep
    learning) emas - soatlik faollik statistikasi (o'rtacha va standart
    og'ish) asosidagi klassik anomaliya aniqlash (Z-score). Bu yondashuv
    tanlangan, chunki: (1) natijasi tushuntirib bo'ladigan (explainable) -
    "nega bu anomaliya deb topildi" savoliga aniq javob beriladi,
    (2) kam ma'lumot bilan ham ishlaydi, (3) haqiqiy sinovdan o'tkazish
    va tekshirish mumkin - "qora quti" ML modeliga qaraganda ancha
    ishonchli SOC muhitida.
    """
    __tablename__ = "device_baselines"

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False, unique=True)

    # Soatlik hodisa (event) chastotasi statistikasi (oxirgi N kun bo'yicha)
    mean_events_per_hour = Column(Integer, default=0)
    stddev_events_per_hour = Column(Integer, default=0)

    # Odatiy faol soatlar (0-23), vergul bilan: masalan "9,10,11,...,18"
    typical_active_hours = Column(String(255))

    lookback_days = Column(Integer, default=30)
    computed_at = Column(DateTime, default=utcnow)
    sample_size = Column(Integer, default=0)          # necha soatlik ma'lumot asosida hisoblangan


class AuditLog(Base):
    """
    Audit Log - yangi TZ 20-bo'lim (Xavfsizlik: Audit Log).

    Dashboard'da bajarilgan har bir MUHIM (yozuvchi) harakatni qayd
    etadi - kim, qachon, nima qildi. Faqat o'qish (GET) so'rovlari
    yozilmaydi (haddan tashqari ko'p yozuv bo'lmasligi uchun) - faqat
    holatni o'zgartiradigan harakatlar: login/logout, foydalanuvchi
    yaratish/faolsizlantirish, alert tasdiqlash, MFA yoqish/o'chirish,
    hisobot yuklab olish.
    """
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False)
    username = Column(String(100), nullable=False)
    action = Column(String(100), nullable=False)          # masalan "login", "acknowledge_alert", "create_user"
    target_type = Column(String(50))                        # masalan "Alert", "User"
    target_id = Column(String(100))                          # nishon ID'si (matn sifatida - turli xil bo'lishi mumkin)
    details = Column(Text)                                    # qo'shimcha kontekst (masalan "role=admin")
    ip_address = Column(String(45))
    success = Column(Boolean, default=True)                    # masalan login muvaffaqiyatsiz bo'lsa False

    __table_args__ = (
        Index("ix_audit_log_timestamp", "timestamp"),
        Index("ix_audit_log_username", "username"),
    )


class User(Base):
    """Dashboard'ga kirish uchun foydalanuvchi (RBAC - yangi TZ 20-bo'lim)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    # Rollar: "admin" (to'liq huquq + foydalanuvchi boshqaruvi),
    # "analyst" (ko'rish + alertlarni tasdiqlash/qayd etish),
    # "viewer" (faqat ko'rish)
    role = Column(String(20), nullable=False, default="viewer")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)

    # --- Autentifikatsiya manbai (yangi TZ 20-bo'lim: LDAP Login) ---
    # "local" - parol shu jadvalda (password_hash) tekshiriladi
    # "ldap"  - parol Active Directory/LDAP serverida tekshiriladi
    #           (password_hash bu holatda ishlatilmaydi, lekin baza
    #           sxemasi soddaligi uchun bo'sh xesh bilan to'ldiriladi)
    auth_source = Column(String(20), nullable=False, default="local")

    # --- MFA / TOTP (yangi TZ 20-bo'lim: MFA) ---
    mfa_secret = Column(String(255))          # Base32 TOTP maxfiy kaliti (shifrlangan holda ~140 belgi,
                                                 # shuning uchun String(64) YETARLI EMAS EDI - PostgreSQL'da
                                                 # bu chegara qat'iy talab qilinadi, SQLite'da esa e'tiborsiz
                                                 # qoldirilgani uchun bu xato faqat PostgreSQL testida chiqdi)
    mfa_enabled = Column(Boolean, default=False)


def _sync_missing_columns(engine):
    """
    "Kamtarona migratsiya" - Alembic o'rniga. `Base.metadata.create_all()`
    FAQAT yangi jadvallarni yaratadi, MAVJUD jadvallarga yangi ustun
    hech qachon qo'shmaydi. Loyiha rivojlanib borgan sari (masalan
    Device jadvaliga risk_score, device_type, agent_last_heartbeat va
    h.k. turli bosqichlarda qo'shilgan) - eski o'rnatishlarda baza
    sxemasi ORM modellaridan orqada qolib ketadi, va bu SQLAlchemy
    xatoligiga olib keladi: "column X does not exist" (bu real
    production'da aniqlangan xato edi).

    Bu funksiya har bir jadval uchun modelda e'lon qilingan ustunlarni
    haqiqiy bazadagilar bilan solishtiradi, va YETISHMAYOTGAN ustunlarni
    avtomatik `ALTER TABLE ... ADD COLUMN` orqali qo'shadi. Faqat
    NULLABLE (majburiy bo'lmagan) ustunlar uchun xavfsiz - bu loyihada
    keyinroq qo'shilgan barcha ustunlar shunday (mavjud qatorlar uchun
    standart qiymat talab qilinmaydi).
    """
    inspector = inspect(engine)
    existing_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue  # yangi jadval - create_all() allaqachon yaratgan

            existing_columns = {col["name"] for col in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in existing_columns:
                    continue
                if not column.nullable:
                    # Xavfsizlik: majburiy (NOT NULL) ustunni avtomatik
                    # qo'shish mavjud qatorlar uchun standart qiymat
                    # talab qiladi - bu holatni qo'lda hal qilish
                    # kerak, jim ravishda o'tkazib yuborilmaydi.
                    logger.warning(
                        f"'{table.name}.{column.name}' yetishmayapti, lekin NOT NULL - "
                        f"avtomatik qo'shilmadi, qo'lda migratsiya kerak"
                    )
                    continue

                col_type = column.type.compile(dialect=engine.dialect)
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {column.name} {col_type}"
                try:
                    conn.execute(text(ddl))
                    logger.info(f"Avtomatik migratsiya: '{table.name}.{column.name}' ustuni qo'shildi")
                except Exception as exc:
                    logger.error(f"'{table.name}.{column.name}' ustunini qo'shib bo'lmadi: {exc}")


def init_db(database_url: str):
    """Bazani va barcha jadvallarni yaratadi (agar mavjud bo'lmasa), va
    mavjud jadvallardagi yetishmayotgan ustunlarni avtomatik qo'shadi."""
    engine = create_engine(database_url, echo=False)
    Base.metadata.create_all(engine)
    _sync_missing_columns(engine)
    return engine
