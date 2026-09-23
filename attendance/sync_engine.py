"""
Sync Engine - Hikvision Face ID terminalidan davomat hodisalarini
tortib olib, `attn_events` jadvaliga yozadi.

Loyihaning umumiy pattern'i: `run_once()` (bitta tsikl) + `run_loop()`
(doimiy ishlash, CLI). Navbat-asosida EMAS (bu yerda "checked" bayrog'i
kerak emas - manba qurilmaning o'zi, u holatni saqlamaydi), o'rniga
`attn_sync_state` jadvalida "oxirgi muvaffaqiyatli sinxronlangan vaqt"
kursor sifatida saqlanadi - keyingi tsikl faqat shu vaqtdan keyingi
hodisalarni so'raydi.

Ishga tushirish:
    python -m attendance.sync_engine
    python -m attendance.sync_engine --loop
    python -m attendance.sync_engine --since-hours 24   # birinchi marta ishga tushganda orqaga qarab
"""
import argparse
import json
import logging
import sys
import os
import time
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config.settings import LOG_LEVEL, ATTENDANCE_SYNC_POLL_SECONDS
from attendance.database import get_session
from attendance.models import AttendanceEvent, Employee, SyncState, utcnow
from attendance.hikvision_client import get_client_from_env, HikvisionAuthError

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("attendance.sync_engine")

SYNC_CURSOR_KEY = "hikvision_last_synced_time"
DEFAULT_BACKFILL_HOURS = 24
# Hodisa vaqti bilan "hozir" orasida shu qadar zaxira (soniya) qoldiriladi -
# qurilma soatining bir oz orqada/oldinda bo'lishi yoki so'rov vaqti bilan
# hodisa yozilish vaqti orasidagi tabiiy kechikishni hisobga olish uchun.
SAFETY_LAG_SECONDS = 5


def _get_cursor(session) -> datetime:
    row = session.query(SyncState).filter_by(key=SYNC_CURSOR_KEY).first()
    if row and row.value:
        try:
            return datetime.fromisoformat(row.value)
        except ValueError:
            pass
    return utcnow() - timedelta(hours=DEFAULT_BACKFILL_HOURS)


def _set_cursor(session, value: datetime):
    row = session.query(SyncState).filter_by(key=SYNC_CURSOR_KEY).first()
    if not row:
        row = SyncState(key=SYNC_CURSOR_KEY)
        session.add(row)
    row.value = value.isoformat()
    row.updated_at = utcnow()


def _parse_event_time(raw_time: str) -> datetime:
    """Hikvision'ning `2024-01-01T09:03:12+05:00` formatidagi vaqtini naive UTC'ga o'giradi."""
    dt = datetime.fromisoformat(raw_time)
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _find_or_create_employee(session, employee_no: str) -> Employee:
    emp = session.query(Employee).filter_by(employee_no=employee_no).first()
    if emp:
        return emp
    emp = Employee(
        employee_no=employee_no,
        full_name=f"Xodim #{employee_no}",
        is_active=True,
    )
    session.add(emp)
    session.flush()
    logger.info(f"Yangi xodim avtomatik yaratildi: #{employee_no} (Face ID terminalidan) - "
                f"to'liq ism HR tomonidan keyinroq to'ldirilishi kerak")
    return emp


def ingest_event(session, raw_event: dict) -> bool:
    """
    Bitta xom ISAPI hodisasini qayta ishlaydi. Qo'shilgan bo'lsa True,
    (dublikat/employeeNoString yo'q bo'lgani sabab) o'tkazib yuborilgan
    bo'lsa False qaytaradi.
    """
    employee_no = (raw_event.get("employeeNoString") or "").strip()
    serial_no = raw_event.get("serialNo")
    raw_time = raw_event.get("time")
    if not employee_no or serial_no is None or not raw_time:
        return False

    device_event_id = f"{serial_no}"
    existing = session.query(AttendanceEvent).filter_by(device_event_id=device_event_id).first()
    if existing:
        return False

    try:
        event_time = _parse_event_time(raw_time)
    except ValueError:
        logger.warning(f"Hodisa vaqtini o'qib bo'lmadi: {raw_time!r}")
        return False

    employee = _find_or_create_employee(session, employee_no)

    event = AttendanceEvent(
        employee_id=employee.id,
        employee_no_raw=employee_no,
        event_time=event_time,
        device_serial=str(raw_event.get("deviceID") or raw_event.get("channelID") or ""),
        major_event=raw_event.get("major"),
        minor_event=raw_event.get("minor"),
        verify_mode=raw_event.get("currentVerifyMode"),
        device_event_id=device_event_id,
        picture_url=raw_event.get("pictureURL"),
        raw_json=json.dumps(raw_event, ensure_ascii=False),
    )
    session.add(event)
    return True


def run_once(since_hours: int = None) -> int:
    """Bitta sinxronlash tsikli. Yangi qo'shilgan hodisalar sonini qaytaradi."""
    session = get_session()
    try:
        client = get_client_from_env()
    except RuntimeError as exc:
        logger.warning(f"Sinxronlash o'tkazib yuborildi: {exc}")
        session.close()
        return 0

    try:
        start_time = _get_cursor(session)
        if since_hours is not None:
            start_time = utcnow() - timedelta(hours=since_hours)
        end_time = utcnow() - timedelta(seconds=SAFETY_LAG_SECONDS)
        if start_time >= end_time:
            return 0

        added = 0
        for raw_event in client.search_acs_events(start_time, end_time):
            if ingest_event(session, raw_event):
                added += 1

        _set_cursor(session, end_time)
        session.commit()
        if added:
            logger.info(f"{added} ta yangi davomat hodisasi yozildi "
                        f"({start_time.isoformat()} -> {end_time.isoformat()})")
        return added
    except HikvisionAuthError as exc:
        logger.error(f"Hikvision autentifikatsiya xatosi: {exc}")
        session.rollback()
        return 0
    except Exception as exc:
        logger.error(f"Sinxronlashda kutilmagan xato: {exc}")
        session.rollback()
        return 0
    finally:
        session.close()


def run_loop(interval: int = None):
    interval = interval or ATTENDANCE_SYNC_POLL_SECONDS
    logger.info(f"Sync engine ishga tushdi (har {interval} soniyada)")
    while True:
        run_once()
        time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Hikvision Face ID -> davomat sinxronlash")
    parser.add_argument("--loop", action="store_true", help="Doimiy tsiklda ishga tushirish")
    parser.add_argument("--interval", type=int, default=None, help="Tsikl orasidagi vaqt (soniya)")
    parser.add_argument("--since-hours", type=int, default=None,
                         help="Kursorni e'tiborsiz qoldirib, shu necha soat orqaga qarab sinxronlash")
    args = parser.parse_args()

    if args.loop:
        run_loop(args.interval)
    else:
        n = run_once(since_hours=args.since_hours)
        print(f"{n} ta yangi hodisa sinxronlandi")
