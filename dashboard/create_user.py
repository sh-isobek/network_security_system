"""
Dashboard uchun foydalanuvchi yaratish/boshqarish skripti.

Ishga tushirish:
    python -m dashboard.create_user --username admin --password '...' --role admin
"""
import argparse
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash

from db.database import get_session
from db.models import User


def create_user(username: str, password: str, role: str = "viewer") -> User:
    if role not in ("admin", "analyst", "viewer"):
        raise ValueError(f"Noto'g'ri rol: {role} (admin/analyst/viewer bo'lishi kerak)")

    session = get_session()
    try:
        existing = session.query(User).filter(User.username == username).first()
        if existing:
            existing.password_hash = generate_password_hash(password)
            existing.role = role
            existing.is_active = True
            session.commit()
            return existing

        user = User(username=username, password_hash=generate_password_hash(password), role=role)
        session.add(user)
        session.commit()
        return user
    finally:
        session.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--role", default="viewer", choices=["admin", "analyst", "viewer"])
    args = ap.parse_args()

    create_user(args.username, args.password, args.role)
    print(f"Foydalanuvchi '{args.username}' ({args.role}) yaratildi/yangilandi.")
