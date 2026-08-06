"""
Autentifikatsiya va RBAC (Role-Based Access Control) - yangi TZ 20-bo'lim.

3 ta rol:
    admin   - to'liq huquq (foydalanuvchi boshqaruvi, barcha sahifalar,
              alertlarni tasdiqlash)
    analyst - ko'rish + alertlarni tasdiqlash (acknowledge)
    viewer  - faqat ko'rish (hech narsani o'zgartira olmaydi)

Parollar `werkzeug.security` orqali xeshlanadi (hech qachon ochiq
matnda saqlanmaydi). Sessiyalar `flask_login` orqali boshqariladi.
"""
from functools import wraps

from flask import redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, current_user

from db.database import get_session
from db.models import User

login_manager = LoginManager()
login_manager.login_view = "login"


class UserWrapper(UserMixin):
    """flask_login uchun SQLAlchemy User obyektini o'rovchi wrapper."""

    def __init__(self, user: User):
        self.id = user.id
        self.username = user.username
        self.role = user.role
        self.is_active_db = user.is_active

    @property
    def is_active(self):
        return self.is_active_db


@login_manager.user_loader
def load_user(user_id):
    session = get_session()
    try:
        user = session.query(User).filter(User.id == int(user_id)).first()
        if user and user.is_active:
            return UserWrapper(user)
        return None
    finally:
        session.close()


# Rollar ierarxiyasi: admin > analyst > viewer
ROLE_LEVEL = {"viewer": 0, "analyst": 1, "admin": 2}


def role_required(min_role: str):
    """
    Route'ni faqat kamida `min_role` darajasidagi foydalanuvchilarga
    ochiq qiladi. Masalan @role_required("analyst") - analyst va admin
    kira oladi, viewer kira olmaydi (403).
    """
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
