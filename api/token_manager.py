"""
API Token boshqaruvi - api/server.py bilan bog'liq, lekin mustaqil
modul (CLI va dashboard'dan ham ishlatiladi).
"""
import hashlib
import logging
import secrets
from datetime import timedelta
from typing import Optional

from db.database import get_session
from db.models import ApiToken, utcnow

logger = logging.getLogger("api_tokens")

TOKEN_PREFIX = "nssk_"  # "Network Security System Key" - token turi aniq bo'lishi uchun


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_token(name: str, created_by: str = "system", expires_days: Optional[int] = None,
                  agent_hostname: Optional[str] = None) -> str:
    """
    Yangi token yaratadi. MUHIM: to'liq token faqat SHU YERDA, bir marta
    qaytariladi - bazada faqat xesh saqlanadi, keyinroq qayta ko'rsatib
    bo'lmaydi (parollar kabi).
    """
    raw_token = TOKEN_PREFIX + secrets.token_urlsafe(32)
    token_hash = _hash_token(raw_token)

    session = get_session()
    try:
        expires_at = utcnow() + timedelta(days=expires_days) if expires_days else None
        entry = ApiToken(
            name=name,
            token_hash=token_hash,
            token_prefix=raw_token[:12],
            created_by=created_by,
            expires_at=expires_at,
            agent_hostname=agent_hostname,
        )
        session.add(entry)
        session.commit()
        logger.info(f"Yangi API token yaratildi: {name} (prefiks: {raw_token[:12]}...)")
    finally:
        session.close()

    return raw_token


def enroll_agent_token(hostname: str, created_by: str = "ad_auto_enroll",
                        expires_days: Optional[int] = None) -> str:
    """
    AD/GPO orqali avtomatik ulanayotgan har bir kompyuter uchun ALOHIDA
    API token chiqaradi - shu paytgacha barcha Windows agentlar BITTA
    umumiy `AGENT_API_KEY`ni ishlatgan (agar u o'g'irlansa/kompaundlansa,
    HAMMA kompyuter uchun bekor qilinishi kerak bo'lardi). Endi GPO
    Deploy skripti birinchi marta ishga tushganda shu funksiyani
    chaqiradi (umumiy bootstrap kalit orqali) va natijada olingan
    ALOHIDA tokenni shu kompyuterda doimiy saqlaydi - shundan keyin
    barcha so'rovlar (check_hash/report_incident/heartbeat) shu ALOHIDA
    token bilan yuboriladi.

    MUHIM (idempotentlik): agar bu hostname uchun avval ham token
    chiqarilgan bo'lsa (masalan kompyuter qayta obraz qilingan va
    mahalliy token fayli yo'qolgan) - eskisi (eskilari) BEKOR qilinadi
    (revoke) va yangisi chiqariladi. Bu eski, endi hech kim ishlatmaydigan
    tokenlarning cheksiz to'planib qolishining oldini oladi.
    """
    session = get_session()
    try:
        stale = (
            session.query(ApiToken)
            .filter(ApiToken.agent_hostname == hostname, ApiToken.revoked.is_(False))
            .all()
        )
        for entry in stale:
            entry.revoked = True
        session.commit()
        if stale:
            logger.info(f"'{hostname}' uchun {len(stale)} ta eski token bekor qilindi (qayta enroll)")
    finally:
        session.close()

    return create_token(
        name=f"{hostname} (AD auto-enroll)",
        created_by=created_by,
        expires_days=expires_days,
        agent_hostname=hostname,
    )


def verify_token(raw_token: str) -> Optional[ApiToken]:
    """
    Token'ni tekshiradi. Muvaffaqiyatli bo'lsa `ApiToken` obyektini
    (attach qilinmagan, faqat ma'lumot uchun) qaytaradi va
    `last_used_at`ni yangilaydi. Aks holda `None`.
    """
    if not raw_token or not raw_token.startswith(TOKEN_PREFIX):
        return None

    token_hash = _hash_token(raw_token)
    session = get_session()
    try:
        entry = session.query(ApiToken).filter(ApiToken.token_hash == token_hash).first()
        if entry is None:
            return None
        if entry.revoked:
            return None
        if entry.expires_at and entry.expires_at < utcnow():
            return None

        entry.last_used_at = utcnow()
        session.commit()

        return ApiToken(
            id=entry.id, name=entry.name, token_prefix=entry.token_prefix,
            created_by=entry.created_by, created_at=entry.created_at,
            last_used_at=entry.last_used_at, expires_at=entry.expires_at, revoked=entry.revoked,
        )
    finally:
        session.close()


def revoke_token(token_id: int) -> bool:
    session = get_session()
    try:
        entry = session.query(ApiToken).filter(ApiToken.id == token_id).first()
        if entry is None:
            return False
        entry.revoked = True
        session.commit()
        return True
    finally:
        session.close()


def list_tokens() -> list:
    session = get_session()
    try:
        return session.query(ApiToken).order_by(ApiToken.created_at.desc()).all()
    finally:
        session.close()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--create", metavar="NAME")
    ap.add_argument("--expires-days", type=int, default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--revoke", type=int, metavar="ID")
    args = ap.parse_args()

    if args.create:
        token = create_token(args.create, created_by="cli", expires_days=args.expires_days)
        print(f"Token yaratildi (BU FAQAT BIR MARTA KO'RSATILADI, saqlab qo'ying):\n{token}")
    elif args.list:
        for t in list_tokens():
            status = "BEKOR QILINGAN" if t.revoked else "faol"
            print(f"[{t.id}] {t.name} ({t.token_prefix}...) - {status} - yaratilgan: {t.created_at}")
    elif args.revoke:
        ok = revoke_token(args.revoke)
        print("Bekor qilindi" if ok else "Token topilmadi")
    else:
        print("--create NAME, --list yoki --revoke ID ishlating")
