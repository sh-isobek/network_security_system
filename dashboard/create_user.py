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


def create_user(username: str, password: str, role: str = "viewer", auth_source: str = "local") -> User:
    if role not in ("admin", "analyst", "viewer"):
        raise ValueError(f"Noto'g'ri rol: {role} (admin/analyst/viewer bo'lishi kerak)")
    if auth_source not in ("local", "ldap"):
        raise ValueError(f"Noto'g'ri auth_source: {auth_source} (local/ldap bo'lishi kerak)")

    session = get_session()
    try:
        # LDAP foydalanuvchilar uchun parol shu jadvalda saqlanmaydi (LDAP
        # serverida tekshiriladi) - lekin ustun NOT NULL bo'lgani uchun
        # ishlatib bo'lmaydigan placeholder xesh yozamiz.
        password_hash = generate_password_hash(password) if auth_source == "local" else generate_password_hash(os.urandom(32).hex())

        existing = session.query(User).filter(User.username == username).first()
        if existing:
            if auth_source == "local":
                existing.password_hash = password_hash
            existing.role = role
            existing.auth_source = auth_source
            existing.is_active = True
            session.commit()
            return existing

        user = User(username=username, password_hash=password_hash, role=role, auth_source=auth_source)
        session.add(user)
        session.commit()
        return user
    finally:
        session.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--username", required=True)
    ap.add_argument("--password", required=True, help="LDAP foydalanuvchilar uchun ham majburiy (sxema uchun), lekin ishlatilmaydi")
    ap.add_argument("--role", default="viewer", choices=["admin", "analyst", "viewer"])
    ap.add_argument("--auth-source", default="local", choices=["local", "ldap"])
    args = ap.parse_args()

    create_user(args.username, args.password, args.role, args.auth_source)
    print(f"Foydalanuvchi '{args.username}' ({args.role}, auth={args.auth_source}) yaratildi/yangilandi.")
