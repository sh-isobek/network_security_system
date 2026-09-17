"""
Audit Log yordamchi modul - super_admin uchun "qaysi rol/foydalanuvchi
nima bajardi" yozuvini qayd etadi (dashboard/audit.py bilan bir xil pattern).
"""
import logging

from attendance.database import get_session
from attendance.models import AttendanceAuditLog

logger = logging.getLogger("attendance.audit")


def log_action(username: str, role: str, action: str, target_type: str = None,
                target_id=None, details: str = None, ip_address: str = None,
                success: bool = True):
    session = get_session()
    try:
        entry = AttendanceAuditLog(
            username=username or "anonim",
            role=role,
            action=action,
            target_type=target_type,
            target_id=str(target_id) if target_id is not None else None,
            details=details,
            ip_address=ip_address,
            success=success,
        )
        session.add(entry)
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"Audit log yozishda xatolik: {exc}")
    finally:
        session.close()
