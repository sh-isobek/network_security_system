"""
Whitelist va Blacklist uchun boshlang'ich (namuna) ma'lumotlarni bazaga kiritadi.

Ishga tushirish:
    python -m engine.seed_lists

Amalda WHITELIST_IPS ro'yxatiga tashkilotning 20+ serveri (1C, domen
kontroller va h.k.) qo'shiladi. BLACKLIST_DOMAINS esa dastlab qo'lda,
keyinchalik ochiq threat-intel manbalaridan (masalan abuse.ch) avtomatik
yuklab olinishi mumkin (2-3-bosqichda kengaytiriladi).
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.database import get_session
from db.models import WhitelistEntry, BlacklistEntry

WHITELIST_IPS = [
    ("172.16.0.10", "1C Server (asosiy)"),
    ("172.16.0.11", "Domen kontroller / AD DNS server"),
]

BLACKLIST_DOMAINS = [
    ("malicious-domain.com", "manual", "Namuna zararli domen (test uchun)"),
    ("phishing-example.net", "manual", "Namuna phishing domen (test uchun)"),
]


def seed():
    session = get_session()
    try:
        for value, desc in WHITELIST_IPS:
            if not session.query(WhitelistEntry).filter_by(value=value).first():
                session.add(WhitelistEntry(value=value, description=desc))

        for value, source, reason in BLACKLIST_DOMAINS:
            if not session.query(BlacklistEntry).filter_by(value=value).first():
                session.add(BlacklistEntry(value=value, source=source, reason=reason))

        session.commit()
        print("Whitelist va Blacklist namunalari muvaffaqiyatli kiritildi.")
    finally:
        session.close()


if __name__ == "__main__":
    seed()
