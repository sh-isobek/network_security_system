"""
Field-level Encryption at Rest - yangi TZ 20-bo'lim (Encryption).

Ba'zi bazadagi maydonlar (masalan MFA maxfiy kaliti) hech qachon ochiq
matnda saqlanmasligi kerak - agar baza fayli/backup o'g'irlansa ham,
bu qiymatlar `ENCRYPTION_KEY` bo'lmasa o'qib bo'lmasin.

`Fernet` (symmetric, AES128-CBC + HMAC) ishlatiladi - kalitni almashtirish
imkoniyati bilan (`MultiFernet`), shuning uchun kalitni davriy
almashtirish (key rotation) ham qo'llab-quvvatlanadi.
"""
import base64
import logging
import os

from cryptography.fernet import Fernet, MultiFernet, InvalidToken

logger = logging.getLogger("field_encryption")


def _get_fernet() -> MultiFernet:
    # MUHIM: ENCRYPTION_KEY'ni modul darajasidagi konstanta sifatida EMAS,
    # har chaqiruvda os.environ'dan dinamik o'qiymiz. Bu loyihada bir
    # necha marta uchragan xato turkumini oldini oladi: agar kalit modul
    # import qilingandan KEYIN o'rnatilsa (masalan testlarda yoki
    # runtime'da .env qayta yuklanganda), eski (bo'sh) qiymat "muzlab"
    # qolib, kalit hech qachon topilmagan bo'lib ko'rinardi.
    encryption_key = os.getenv("ENCRYPTION_KEY", "")
    encryption_key_old = os.getenv("ENCRYPTION_KEY_OLD", "")

    keys = []
    for key_str in (encryption_key, encryption_key_old):
        if key_str:
            keys.append(Fernet(key_str.encode() if isinstance(key_str, str) else key_str))
    if not keys:
        raise RuntimeError(
            "ENCRYPTION_KEY sozlanmagan. Yaratish uchun: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return MultiFernet(keys)


def generate_key() -> str:
    """Yangi shifrlash kalitini generatsiya qiladi (.env'ga qo'yish uchun)."""
    return Fernet.generate_key().decode()


def is_configured() -> bool:
    return bool(os.getenv("ENCRYPTION_KEY", ""))


def encrypt_value(plaintext: str) -> str:
    """Matnni shifrlaydi. Natija - base64 matn ko'rinishida (bazaga String ustunga yozsa bo'ladi)."""
    if plaintext is None:
        return None
    f = _get_fernet()
    return f.encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_value(ciphertext: str) -> str:
    """
    Shifrlangan matnni ochadi. Agar noto'g'ri kalit yoki buzilgan
    ma'lumot bo'lsa, `ValueError` ko'taradi (chaqiruvchi kod buni
    aniq boshqarishi kerak - jim ravishda noto'g'ri qiymat qaytarilmaydi).
    """
    if ciphertext is None:
        return None
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        raise ValueError("Shifrni ochib bo'lmadi - noto'g'ri ENCRYPTION_KEY yoki buzilgan ma'lumot")


def is_encrypted(value: str) -> bool:
    """
    Berilgan qiymat shifrlangan (Fernet token) ko'rinishidami, tekshiradi.
    Migratsiya davrida (eski ochiq matn qiymatlar bilan yangi shifrlangan
    qiymatlar aralash bo'lganda) foydali.
    """
    if not value:
        return False
    try:
        base64.urlsafe_b64decode(value.encode("utf-8") + b"=" * (-len(value) % 4))
        return value.startswith("gAAAAA")  # Fernet tokenlari doim shu prefiks bilan boshlanadi
    except Exception:
        return False


def encrypt_if_configured(plaintext: str) -> str:
    """
    Agar ENCRYPTION_KEY sozlangan bo'lsa shifrlaydi, aks holda ochiq
    matnni o'zgarishsiz qaytaradi (ENCRYPTION_KEY sozlanmagan dev/test
    muhitlarida ishlashni davom ettirish uchun - lekin production'da
    ENCRYPTION_KEY albatta sozlanishi TAVSIYA ETILADI).
    """
    if not is_configured():
        logger.warning("ENCRYPTION_KEY sozlanmagan - qiymat OCHIQ MATNDA saqlanadi")
        return plaintext
    return encrypt_value(plaintext)


def decrypt_if_needed(value: str) -> str:
    """
    Agar qiymat shifrlangan bo'lsa ochadi, aks holda (eski ochiq matn
    yozuvlar - migratsiya davri uchun) o'zgarishsiz qaytaradi.
    """
    if is_encrypted(value):
        return decrypt_value(value)
    return value
