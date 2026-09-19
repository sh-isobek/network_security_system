"""
Autentifikatsiya va RBAC - Davomat Dashboard uchun.

3 ta rol (`attendance/models.py`da e'lon qilingan):
    super_admin - to'liq huquq (xodim qo'shish/o'chirish, foydalanuvchi
                  boshqaruvi, Audit Log)
    hr_admin    - xodim qo'shish/o'CHIRISH huquqisiz (aniq talab
                  bo'yicha) - lekin tahrirlash, oylik hisobot, ogohlantirish/
                  jarima belgilash mumkin
    viewer      - faqat kuzatuv: % va diagrammalar (kechikish/erta
                  kelish/ketish statusi) - boshqa hech narsa
"""
from functools import wraps

from flask import redirect, url_for, abort
from flask_login import LoginManager, UserMixin, current_user
from werkzeug.security import check_password_hash

from attendance.database import get_session
from attendance.models import AttendanceUser, ROLE_SUPER_ADMIN, ROLE_HR_ADMIN, ROLE_VIEWER

login_manager = LoginManager()
login_manager.login_view = "login"

ROLE_LEVEL = {ROLE_VIEWER: 0, ROLE_HR_ADMIN: 1, ROLE_SUPER_ADMIN: 2}


class UserWrapper(UserMixin):
    def __init__(self, user: AttendanceUser):
        self.id = user.id
        self.username = user.username
        self.role = user.role
        self.is_active_db = user.is_active

    @property
    def is_active(self):
        return self.is_active_db


def verify_credentials(user: AttendanceUser, password: str) -> bool:
    return check_password_hash(user.password_hash, password)


@login_manager.user_loader
def load_user(user_id):
    session = get_session()
    try:
        user = session.query(AttendanceUser).filter(AttendanceUser.id == int(user_id)).first()
        if user and user.is_active:
            return UserWrapper(user)
        return None
    finally:
        session.close()


def role_required(min_role: str):
    """Kamida `min_role` darajasidagi rol talab qilinadi (viewer < hr_admin < super_admin)."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("login"))
            user_level = ROLE_LEVEL.get(current_user.role, -1)
            required_level = ROLE_LEVEL.get(min_role, 99)
            if user_level < required_level:
                abort(403)
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def super_admin_only(fn):
    """Xodim qo'shish/o'chirish va foydalanuvchi boshqaruvi kabi FAQAT super_admin amallari uchun."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.role != ROLE_SUPER_ADMIN:
            abort(403)
        return fn(*args, **kwargs)
    return wrapper
