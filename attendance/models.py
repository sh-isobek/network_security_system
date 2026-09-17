"""
Davomat subtizimining ORM modellari.

Asosiy loyihaning `db/models.py`sidan ATAYLAB ALOHIDA, mustaqil `Base`
ishlatiladi - bu ikki domenni (tarmoq xavfsizligi va HR davomat)
bir-biridan mustaqil qiladi (jadval nomlari `attn_` prefiksi bilan),
lekin ikkalasi ham bir xil `DATABASE_URL` (config/settings.py) orqali
BIR XIL bazaga (SQLite dev'da yoki PostgreSQL production'da) yoziladi -
kod o'zgarishisiz ikkala muhitda ham ishlaydi (loyihaning umumiy
arxitektura qarori).
"""
from datetime import datetime, timezone, date as date_cls

from sqlalchemy import (
    Column, Integer, String, DateTime, Date, Time, Text, Boolean,
    ForeignKey, Float, Index, UniqueConstraint, inspect, text,
)
from sqlalchemy.orm import declarative_base, relationship

AttnBase = declarative_base()


def utcnow() -> datetime:
    """Naive UTC datetime (db/models.py::utcnow bilan bir xil pattern)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---- Rollar (RBAC) ----
ROLE_SUPER_ADMIN = "super_admin"
ROLE_HR_ADMIN = "hr_admin"
ROLE_VIEWER = "viewer"
ALL_ROLES = (ROLE_SUPER_ADMIN, ROLE_HR_ADMIN, ROLE_VIEWER)

# ---- Kunlik kelish/ketish statuslari ----
ARRIVAL_EARLY = "erta_keldi"
ARRIVAL_ON_TIME = "vaqtida"
ARRIVAL_LATE = "kechikdi"
ARRIVAL_ABSENT = "kelmadi"

DEPARTURE_ON_TIME = "vaqtida_ketdi"
DEPARTURE_EARLY = "erta_ketdi"
DEPARTURE_LATE = "kech_ketdi"
DEPARTURE_NONE = "yoq"  # kelmagan yoki hali ketmagan (kun tugamagan)


class Employee(AttnBase):
    """Xodim - Face ID terminalidagi `employeeNoString` orqali bog'lanadi."""
    __tablename__ = "attn_employees"

    id = Column(Integer, primary_key=True)
    employee_no = Column(String(64), nullable=False, unique=True)  # device employeeNoString
    full_name = Column(String(200), nullable=False)
    department = Column(String(120))
    position = Column(String(120))
    phone = Column(String(50))
    hire_date = Column(Date)
    is_active = Column(Boolean, default=True)
    schedule_id = Column(Integer, ForeignKey("attn_work_schedules.id"), nullable=True)
    created_at = Column(DateTime, default=utcnow)

    schedule = relationship("WorkSchedule")

    def __repr__(self):
        return f"<Employee {self.employee_no} {self.full_name}>"


class WorkSchedule(AttnBase):
    """Ish jadvali (boshlanish/tugash vaqti + kechikish uchun imtiyoz)."""
    __tablename__ = "attn_work_schedules"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False, unique=True)
    work_start = Column(Time, nullable=False)
    work_end = Column(Time, nullable=False)
    # Kechikish/erta-ketish uchun imtiyoz (daqiqa) - shu chegaragacha "vaqtida" hisoblanadi
    grace_late_minutes = Column(Integer, default=0)
    grace_early_leave_minutes = Column(Integer, default=0)
    # Ish kunlari: ISO hafta kuni raqamlari, vergul bilan ("1,2,3,4,5" = Dush-Juma)
    workdays = Column(String(20), default="1,2,3,4,5")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    def workday_set(self):
        return {int(x) for x in self.workdays.split(",") if x.strip()}


class AttendanceEvent(AttnBase):
    """Face ID terminalidan kelgan xom hodisa (har bir yuz tanish/kirish)."""
    __tablename__ = "attn_events"

    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer, ForeignKey("attn_employees.id"), nullable=True)
    employee_no_raw = Column(String(64))  # moslik topilmasa ham saqlanadi (keyin qayta bog'lash uchun)
    event_time = Column(DateTime, nullable=False)  # UTC
    device_serial = Column(String(64))
    major_event = Column(Integer)
    minor_event = Column(Integer)
    verify_mode = Column(String(50))  # masalan "face"
    # Qurilmaning o'z hodisa identifikatori (serialNo maydoni) - dublikatni oldini olish uchun
    device_event_id = Column(String(64), nullable=False, unique=True)
    picture_url = Column(String(500))
    raw_json = Column(Text)
    synced_at = Column(DateTime, default=utcnow)

    employee = relationship("Employee")

    __table_args__ = (
        Index("ix_attn_events_employee_time", "employee_id", "event_time"),
    )


class DailyAttendance(AttnBase):
    """Har bir xodim uchun, har bir ish kuni uchun hisoblangan yakuniy status."""
    __tablename__ = "attn_daily_records"

    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer, ForeignKey("attn_employees.id"), nullable=False)
    work_date = Column(Date, nullable=False)
    first_seen = Column(DateTime)  # UTC
    last_seen = Column(DateTime)   # UTC
    arrival_status = Column(String(20))     # erta_keldi/vaqtida/kechikdi/kelmadi
    departure_status = Column(String(20))   # vaqtida_ketdi/erta_ketdi/kech_ketdi/yoq
    late_minutes = Column(Integer, default=0)
    early_leave_minutes = Column(Integer, default=0)
    computed_at = Column(DateTime, default=utcnow)

    employee = relationship("Employee")

    __table_args__ = (
        UniqueConstraint("employee_id", "work_date", name="uq_attn_daily_emp_date"),
        Index("ix_attn_daily_date", "work_date"),
    )


class AttendanceUser(AttnBase):
    """Dashboard foydalanuvchisi - 3 rol: super_admin/hr_admin/viewer."""
    __tablename__ = "attn_users"

    id = Column(Integer, primary_key=True)
    username = Column(String(100), nullable=False, unique=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default=ROLE_VIEWER)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)
    last_login = Column(DateTime)


class AttendanceAuditLog(AttnBase):
    """Super admin uchun: qaysi rol/foydalanuvchi nima bajarganini qayd etadi."""
    __tablename__ = "attn_audit_log"

    id = Column(Integer, primary_key=True)
    username = Column(String(100))
    role = Column(String(20))
    action = Column(String(100), nullable=False)
    target_type = Column(String(50))
    target_id = Column(String(100))
    details = Column(Text)
    ip_address = Column(String(64))
    success = Column(Boolean, default=True)
    timestamp = Column(DateTime, default=utcnow)


class Penalty(AttnBase):
    """HR admin (yoki super admin) tomonidan berilgan ogohlantirish/jarima."""
    __tablename__ = "attn_penalties"

    id = Column(Integer, primary_key=True)
    employee_id = Column(Integer, ForeignKey("attn_employees.id"), nullable=False)
    daily_record_id = Column(Integer, ForeignKey("attn_daily_records.id"), nullable=True)
    penalty_type = Column(String(20), nullable=False)  # "ogohlantirish" / "jarima"
    amount = Column(Float, nullable=True)  # faqat jarima uchun
    reason = Column(Text)
    issued_by = Column(String(100))
    issued_at = Column(DateTime, default=utcnow)

    employee = relationship("Employee")


class DailyReportLog(AttnBase):
    """Kunlik hisobot allaqachon yuborilganmi - takroriy yuborishni oldini olish uchun."""
    __tablename__ = "attn_daily_report_log"

    id = Column(Integer, primary_key=True)
    report_date = Column(Date, nullable=False, unique=True)
    telegram_sent = Column(Boolean, default=False)
    email_sent = Column(Boolean, default=False)
    sent_at = Column(DateTime, default=utcnow)


class SyncState(AttnBase):
    """Oddiy kalit/qiymat holat jadvali - masalan 'oxirgi sinxronlangan vaqt'."""
    __tablename__ = "attn_sync_state"

    key = Column(String(100), primary_key=True)
    value = Column(String(200))
    updated_at = Column(DateTime, default=utcnow)


def init_db(database_url: str):
    """Barcha `attn_*` jadvallarini yaratadi (mavjud bo'lmasa) va engine qaytaradi."""
    from sqlalchemy import create_engine
    engine = create_engine(database_url)
    AttnBase.metadata.create_all(engine)
    _sync_missing_columns(engine)
    return engine


def _sync_missing_columns(engine):
    """
    Asosiy loyihaning `db/models.py::_sync_missing_columns()` bilan bir
    xil pattern - yangi (nullable) ustun modelga qo'shilsa, mavjud
    jadvalga avtomatik `ALTER TABLE ... ADD COLUMN` bilan qo'shiladi.
    """
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table in AttnBase.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            existing_cols = {c["name"] for c in insp.get_columns(table.name)}
            for col in table.columns:
                if col.name in existing_cols:
                    continue
                if not col.nullable and col.default is None and col.server_default is None:
                    continue
                col_type = col.type.compile(engine.dialect)
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {col.name} {col_type}'))
