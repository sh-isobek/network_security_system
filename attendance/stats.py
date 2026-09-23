"""
Davomat statistikasi - Dashboard grafiklari VA kunlik hisobot uchun
UMUMIY hisoblash mantig'i (ikki marta yozmaslik uchun).
"""
from datetime import date

from attendance.models import (
    DailyAttendance, Employee,
    ARRIVAL_EARLY, ARRIVAL_ON_TIME, ARRIVAL_LATE, ARRIVAL_ABSENT,
    DEPARTURE_ON_TIME, DEPARTURE_EARLY, DEPARTURE_LATE,
)


def _pct(part: int, total: int) -> float:
    if not total:
        return 0.0
    return round(part * 100.0 / total, 1)


def compute_period_stats(session, start_date: date, end_date: date, department: str = None) -> dict:
    """
    [start_date, end_date] (ikkalasi ham qamrab olinadi) oralig'idagi
    BARCHA hisoblangan kunlik yozuvlar (dam olish kunlari - arrival_status
    NULL - hisobga olinmaydi) asosida % taqsimotini qaytaradi.

    Kuzatuvchi (viewer) rolining dashboard'i aynan shu funksiyadan foydalanadi.
    """
    query = session.query(DailyAttendance).filter(
        DailyAttendance.work_date >= start_date,
        DailyAttendance.work_date <= end_date,
        DailyAttendance.arrival_status.isnot(None),
    )
    if department:
        query = query.join(Employee).filter(Employee.department == department)

    records = query.all()
    total = len(records)

    arrival_counts = {
        ARRIVAL_EARLY: 0, ARRIVAL_ON_TIME: 0, ARRIVAL_LATE: 0, ARRIVAL_ABSENT: 0,
    }
    departure_counts = {
        DEPARTURE_ON_TIME: 0, DEPARTURE_EARLY: 0, DEPARTURE_LATE: 0,
    }
    departure_total = 0

    for rec in records:
        if rec.arrival_status in arrival_counts:
            arrival_counts[rec.arrival_status] += 1
        if rec.arrival_status != ARRIVAL_ABSENT and rec.departure_status in departure_counts:
            departure_counts[rec.departure_status] += 1
            departure_total += 1

    return {
        "total_records": total,
        "arrival": {
            "erta_keldi": {"count": arrival_counts[ARRIVAL_EARLY], "pct": _pct(arrival_counts[ARRIVAL_EARLY], total)},
            "vaqtida": {"count": arrival_counts[ARRIVAL_ON_TIME], "pct": _pct(arrival_counts[ARRIVAL_ON_TIME], total)},
            "kechikdi": {"count": arrival_counts[ARRIVAL_LATE], "pct": _pct(arrival_counts[ARRIVAL_LATE], total)},
            "kelmadi": {"count": arrival_counts[ARRIVAL_ABSENT], "pct": _pct(arrival_counts[ARRIVAL_ABSENT], total)},
        },
        "departure": {
            "vaqtida_ketdi": {"count": departure_counts[DEPARTURE_ON_TIME], "pct": _pct(departure_counts[DEPARTURE_ON_TIME], departure_total)},
            "erta_ketdi": {"count": departure_counts[DEPARTURE_EARLY], "pct": _pct(departure_counts[DEPARTURE_EARLY], departure_total)},
            "kech_ketdi": {"count": departure_counts[DEPARTURE_LATE], "pct": _pct(departure_counts[DEPARTURE_LATE], departure_total)},
        },
    }


def late_and_absent_for_date(session, work_date: date):
    """Kunlik hisobot uchun: kechikkan va kelmagan xodimlar ro'yxati (ism + tafsilot bilan)."""
    records = (
        session.query(DailyAttendance)
        .join(Employee)
        .filter(DailyAttendance.work_date == work_date, DailyAttendance.arrival_status.isnot(None))
        .all()
    )
    late = [r for r in records if r.arrival_status == ARRIVAL_LATE]
    absent = [r for r in records if r.arrival_status == ARRIVAL_ABSENT]
    late.sort(key=lambda r: -r.late_minutes)
    return late, absent
