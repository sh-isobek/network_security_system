"""
Kunlik davomat kalkulyatori.

`attn_events` (Face ID terminalidan kelgan xom hodisalar) asosida, har
bir xodim uchun, har bir ish kuni uchun YAKUNIY statusni hisoblaydi va
`attn_daily_records`ga yozadi:

  - Kelish: erta_keldi / vaqtida / kechikdi / kelmadi
  - Ketish:  vaqtida_ketdi / erta_ketdi / kech_ketdi / yoq (kelmagan
             yoki kun hali tugamagan)

HALOL CHEKLOV: DS-K1T342MFWX odatda faqat "yuz tanildi" hodisasini
yuboradi - kirish/chiqish (check-in/check-out) rejimini ALOHIDA
sozlamasa, hodisada bu farq YO'Q. Shuning uchun bu modul KUNNING
BIRINCHI ko'rilgan hodisasini "kelish", OXIRGI ko'rilgan hodisasini
"ketish" deb hisoblaydi - agar xodim kun davomida FAQAT BIR MARTA
(masalan faqat kirishda) terminaldan o'tsa, "kelish" VA "ketish"
statusi BIR XIL hodisadan hisoblanadi (bu haqiqiy cheklov, terminalning
o'zida "Attendance Mode" yoqilgan bo'lsa - `attendanceStatus` maydoni
orqali - kelajakda aniqroq ajratish mumkin).

Ishga tushirish:
    python -m attendance.calculator                  # kecha uchun
    python -m attendance.calculator --date 2026-09-16
    python -m attendance.calculator --loop
"""
import argparse
import logging
import os
import sys
import time
from datetime import date, datetime, timedelta, time as time_cls

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import (
    LOG_LEVEL, TIMEZONE_OFFSET_HOURS, ATTENDANCE_DEFAULT_WORK_START,
    ATTENDANCE_DEFAULT_WORK_END, ATTENDANCE_DEFAULT_GRACE_LATE_MINUTES,
    ATTENDANCE_DEFAULT_GRACE_EARLY_LEAVE_MINUTES,
)
from attendance.database import get_session
from attendance.models import (
    AttendanceEvent, Employee, WorkSchedule, DailyAttendance, utcnow,
    ARRIVAL_EARLY, ARRIVAL_ON_TIME, ARRIVAL_LATE, ARRIVAL_ABSENT,
    DEPARTURE_ON_TIME, DEPARTURE_EARLY, DEPARTURE_LATE, DEPARTURE_NONE,
)

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("attendance.calculator")

CALC_LOOP_INTERVAL_SECONDS = 900  # 15 daqiqa - kunning davomida jonli hisoblash uchun


def _parse_hhmm(value: str) -> time_cls:
    h, m = value.split(":")
    return time_cls(int(h), int(m))


def get_or_create_default_schedule(session) -> WorkSchedule:
    sched = session.query(WorkSchedule).filter_by(is_default=True).first()
    if sched:
        return sched
    sched = WorkSchedule(
        name="Standart",
        work_start=_parse_hhmm(ATTENDANCE_DEFAULT_WORK_START),
        work_end=_parse_hhmm(ATTENDANCE_DEFAULT_WORK_END),
        grace_late_minutes=ATTENDANCE_DEFAULT_GRACE_LATE_MINUTES,
        grace_early_leave_minutes=ATTENDANCE_DEFAULT_GRACE_EARLY_LEAVE_MINUTES,
        workdays="1,2,3,4,5",
        is_default=True,
    )
    session.add(sched)
    session.flush()
    return sched


def _local_day_utc_range(work_date: date):
    """Mahalliy kalendar kunining boshi/oxirini UTC'ga o'girib qaytaradi."""
    local_start = datetime.combine(work_date, time_cls(0, 0))
    utc_start = local_start - timedelta(hours=TIMEZONE_OFFSET_HOURS)
    utc_end = utc_start + timedelta(days=1)
    return utc_start, utc_end


def _to_local(dt_utc: datetime) -> datetime:
    return dt_utc + timedelta(hours=TIMEZONE_OFFSET_HOURS)


def compute_arrival(first_local: datetime, work_date: date, schedule: WorkSchedule):
    work_start_dt = datetime.combine(work_date, schedule.work_start)
    grace_end = work_start_dt + timedelta(minutes=schedule.grace_late_minutes or 0)
    if first_local < work_start_dt:
        return ARRIVAL_EARLY, 0
    if first_local <= grace_end:
        return ARRIVAL_ON_TIME, 0
    late_minutes = int((first_local - grace_end).total_seconds() // 60)
    return ARRIVAL_LATE, late_minutes


def compute_departure(last_local: datetime, work_date: date, schedule: WorkSchedule):
    work_end_dt = datetime.combine(work_date, schedule.work_end)
    grace = timedelta(minutes=schedule.grace_early_leave_minutes or 0)
    window_start = work_end_dt - grace
    window_end = work_end_dt + grace
    if last_local < window_start:
        early_minutes = int((window_start - last_local).total_seconds() // 60)
        return DEPARTURE_EARLY, early_minutes
    if last_local <= window_end:
        return DEPARTURE_ON_TIME, 0
    return DEPARTURE_LATE, 0


def compute_employee_day(session, employee: Employee, work_date: date) -> DailyAttendance:
    schedule = employee.schedule or get_or_create_default_schedule(session)

    record = session.query(DailyAttendance).filter_by(
        employee_id=employee.id, work_date=work_date
    ).first()
    if not record:
        record = DailyAttendance(employee_id=employee.id, work_date=work_date)
        session.add(record)

    if work_date.isoweekday() not in schedule.workday_set():
        # Dam olish kuni - hisoblanmaydi (bo'sh qoldiriladi, "kelmadi" EMAS)
        record.first_seen = None
        record.last_seen = None
        record.arrival_status = None
        record.departure_status = None
        record.late_minutes = 0
        record.early_leave_minutes = 0
        record.computed_at = utcnow()
        return record

    utc_start, utc_end = _local_day_utc_range(work_date)
    events = (
        session.query(AttendanceEvent)
        .filter(
            AttendanceEvent.employee_id == employee.id,
            AttendanceEvent.event_time >= utc_start,
            AttendanceEvent.event_time < utc_end,
        )
        .order_by(AttendanceEvent.event_time.asc())
        .all()
    )

    if not events:
        record.first_seen = None
        record.last_seen = None
        record.arrival_status = ARRIVAL_ABSENT
        record.departure_status = DEPARTURE_NONE
        record.late_minutes = 0
        record.early_leave_minutes = 0
        record.computed_at = utcnow()
        return record

    first_seen = events[0].event_time
    last_seen = events[-1].event_time

    arrival_status, late_minutes = compute_arrival(_to_local(first_seen), work_date, schedule)
    departure_status, early_minutes = compute_departure(_to_local(last_seen), work_date, schedule)

    record.first_seen = first_seen
    record.last_seen = last_seen
    record.arrival_status = arrival_status
    record.departure_status = departure_status
    record.late_minutes = late_minutes
    record.early_leave_minutes = early_minutes
    record.computed_at = utcnow()
    return record


def run_once(target_date: date = None) -> int:
    """
    Kecha (standart) yoki `target_date` uchun BARCHA faol xodimlar
    davomatini hisoblaydi. Yangilangan/yaratilgan yozuvlar sonini qaytaradi.
    """
    if target_date is None:
        target_date = (utcnow() + timedelta(hours=TIMEZONE_OFFSET_HOURS) - timedelta(days=1)).date()

    session = get_session()
    try:
        employees = session.query(Employee).filter_by(is_active=True).all()
        count = 0
        for emp in employees:
            compute_employee_day(session, emp, target_date)
            count += 1
        session.commit()
        logger.info(f"{count} ta xodim uchun {target_date} kuni davomati hisoblandi")
        return count
    except Exception as exc:
        session.rollback()
        logger.error(f"Davomat hisoblashda xato: {exc}")
        return 0
    finally:
        session.close()


def run_loop(interval: int = CALC_LOOP_INTERVAL_SECONDS):
    logger.info(f"Calculator ishga tushdi (har {interval} soniyada, kecha + bugun uchun)")
    while True:
        local_today = (utcnow() + timedelta(hours=TIMEZONE_OFFSET_HOURS)).date()
        run_once(local_today - timedelta(days=1))
        run_once(local_today)  # bugungi kun uchun ham - Dashboard'da "jonli" ko'rinish
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kunlik davomat statusini hisoblash")
    parser.add_argument("--date", type=str, default=None, help="YYYY-MM-DD (standart: kecha)")
    parser.add_argument("--loop", action="store_true")
    args = parser.parse_args()

    target = date.fromisoformat(args.date) if args.date else None
    if args.loop:
        run_loop()
    else:
        n = run_once(target)
        print(f"{n} ta xodim uchun hisoblandi")
