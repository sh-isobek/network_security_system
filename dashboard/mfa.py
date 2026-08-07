"""
MFA (Multi-Factor Authentication) - yangi TZ 20-bo'lim.

TOTP (Time-based One-Time Password, RFC 6238) standarti - Google
Authenticator, Microsoft Authenticator, Authy kabi barcha standart
autentifikator ilovalar bilan mos ishlaydi.

`pyotp` (TOTP generatsiya/tekshirish) va `qrcode` (QR-kod yaratish -
foydalanuvchi telefon kamerasi bilan skanerlash uchun) ishlatiladi.
"""
import base64
import io

import pyotp
import qrcode

ISSUER_NAME = "Xavfsizlik Monitoring Tizimi"


def generate_secret() -> str:
    """Yangi Base32 TOTP maxfiy kalitini generatsiya qiladi."""
    return pyotp.random_base32()


def get_provisioning_uri(secret: str, username: str) -> str:
    """Autentifikator ilovasi tushunadigan otpauth:// URI'ni quradi."""
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER_NAME)


def generate_qr_code_data_uri(secret: str, username: str) -> str:
    """
    QR-kodni PNG rasm sifatida generatsiya qilib, HTML <img> tegida
    to'g'ridan-to'g'ri ishlatish uchun base64 data URI qaytaradi
    (alohida fayl saqlash shart emas).
    """
    uri = get_provisioning_uri(secret, username)
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/png;base64,{b64}"


def verify_code(secret: str, code: str) -> bool:
    """
    Foydalanuvchi kiritgan 6 xonali kodni tekshiradi.
    `valid_window=1` - vaqt sinxronizatsiyasidagi kichik farqlarga
    (oldingi/keyingi 30 soniyalik oyna) tolerantlik beradi.
    """
    if not secret or not code:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def get_current_code(secret: str) -> str:
    """Faqat test/debug uchun - joriy amaldagi kodni qaytaradi."""
    return pyotp.TOTP(secret).now()
