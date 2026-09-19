"""
Boshlang'ich Dashboard foydalanuvchisini (odatda super_admin) yaratish uchun CLI.

    python -m attendance.create_user --username admin --password '...' --role super_admin
"""
import argparse
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from werkzeug.security import generate_password_hash

from attendance.database import get_session
from attendance.models import AttendanceUser, ALL_ROLES


def create_user(username: str, password: str, role: str):
    if role not in ALL_ROLES:
        raise ValueError(f"Noto'g'ri rol: {role}. Ruxsat etilgan: {ALL_ROLES}")

    session = get_session()
    try:
        existing = session.query(AttendanceUser).filter_by(username=username).first()
        if existing:
            print(f"Xato: '{username}' allaqachon mavjud")
            return False

        user = AttendanceUser(
            username=username,
            password_hash=generate_password_hash(password),
            role=role,
            is_active=True,
        )
        session.add(user)
        session.commit()
        print(f"Foydalanuvchi yaratildi: {username} (rol: {role})")
        return True
    finally:
        session.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Davomat Dashboard foydalanuvchisini yaratish")
    parser.add_argument("--username", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument("--role", required=True, choices=ALL_ROLES)
    args = parser.parse_args()
    create_user(args.username, args.password, args.role)
