"""
Audit Log yordamchi modul - dashboard'dagi muhim harakatlarni qayd etadi.
"""
import logging

from db.database import get_session
from db.models import AuditLog

logger = logging.getLogger("audit")


def log_action(username: str, action: str, target_type: str = None, target_id=None,
                details: str = None, ip_address: str = None, success: bool = True):
    """
    Audit yozuvini bazaga qo'shadi. Xatolik bo'lsa (masalan baza band)
    exception ko'tarmaydi va faqat log yozadi - audit yozish muvaffaqiyatsiz
    bo'lgani uchun asosiy amal (masalan login) to'xtab qolmasligi kerak.
    """
    session = get_session()
    try:
        entry = AuditLog(
            username=username or "anonim",
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
