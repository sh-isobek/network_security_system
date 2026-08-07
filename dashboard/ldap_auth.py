"""
LDAP/Active Directory Login - yangi TZ 20-bo'lim.

`ldap3` kutubxonasi (pure-Python, kompilyatsiya shart emas - `python-ldap`
kabi C kutubxonalariga bog'liq emas) orqali ishlaydi.

Ikki autentifikatsiya usuli qo'llab-quvvatlanadi:
  1. TO'G'RIDAN-TO'G'RI BIND (sodda, kichik tashkilotlar uchun):
     foydalanuvchi nomidan DN quriladi (LDAP_BIND_DN_TEMPLATE) va shu
     bilan to'g'ridan-to'g'ri bind qilinadi.
  2. QIDIRUV + BIND (Active Directory uchun tavsiya etiladi):
     avval xizmat hisobi (service account) bilan bind qilinadi,
     foydalanuvchi qidiriladi, topilgan DN bilan qayta bind qilinadi
     (parolni tekshirish uchun).

.env sozlamalari:
    LDAP_SERVER=ldap://172.16.0.20:389
    LDAP_AUTH_METHOD=direct_bind   # yoki search_bind
    LDAP_BIND_DN_TEMPLATE=cn={username},ou=people,dc=company,dc=local
    # search_bind uchun qo'shimcha:
    LDAP_BASE_DN=dc=company,dc=local
    LDAP_SERVICE_DN=cn=admin,dc=company,dc=local
    LDAP_SERVICE_PASSWORD=...
    LDAP_USER_SEARCH_FILTER=(cn={username})
"""
import logging
import os

from ldap3 import Server, Connection, ALL, SIMPLE

logger = logging.getLogger("ldap_auth")

LDAP_SERVER = os.getenv("LDAP_SERVER", "")
LDAP_AUTH_METHOD = os.getenv("LDAP_AUTH_METHOD", "direct_bind")
LDAP_BIND_DN_TEMPLATE = os.getenv("LDAP_BIND_DN_TEMPLATE", "cn={username},ou=people,dc=company,dc=local")
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "")
LDAP_SERVICE_DN = os.getenv("LDAP_SERVICE_DN", "")
LDAP_SERVICE_PASSWORD = os.getenv("LDAP_SERVICE_PASSWORD", "")
LDAP_USER_SEARCH_FILTER = os.getenv("LDAP_USER_SEARCH_FILTER", "(cn={username})")
LDAP_TIMEOUT = int(os.getenv("LDAP_TIMEOUT", "5"))


def is_ldap_configured() -> bool:
    return bool(LDAP_SERVER)


def _direct_bind(username: str, password: str) -> bool:
    dn = LDAP_BIND_DN_TEMPLATE.format(username=username)
    server = Server(LDAP_SERVER, get_info=None, connect_timeout=LDAP_TIMEOUT)
    try:
        conn = Connection(server, user=dn, password=password, authentication=SIMPLE, auto_bind=True)
        conn.unbind()
        return True
    except Exception as exc:
        logger.info(f"LDAP bind muvaffaqiyatsiz ({username}): {exc}")
        return False


def _search_bind(username: str, password: str) -> bool:
    server = Server(LDAP_SERVER, get_info=ALL, connect_timeout=LDAP_TIMEOUT)
    try:
        # 1) Xizmat hisobi bilan bind qilib, foydalanuvchini qidiramiz
        service_conn = Connection(
            server, user=LDAP_SERVICE_DN, password=LDAP_SERVICE_PASSWORD,
            authentication=SIMPLE, auto_bind=True,
        )
        search_filter = LDAP_USER_SEARCH_FILTER.format(username=username)
        service_conn.search(LDAP_BASE_DN, search_filter, attributes=["cn"])

        if not service_conn.entries:
            logger.info(f"LDAP qidiruvda topilmadi: {username}")
            service_conn.unbind()
            return False

        user_dn = service_conn.entries[0].entry_dn
        service_conn.unbind()

        # 2) Topilgan DN bilan foydalanuvchi paroli orqali qayta bind (haqiqiy tekshiruv)
        user_conn = Connection(server, user=user_dn, password=password, authentication=SIMPLE, auto_bind=True)
        user_conn.unbind()
        return True
    except Exception as exc:
        logger.info(f"LDAP search+bind muvaffaqiyatsiz ({username}): {exc}")
        return False


def authenticate_ldap(username: str, password: str) -> bool:
    """
    LDAP serverida foydalanuvchi/parolni tekshiradi.
    Muvaffaqiyatli bo'lsa True, aks holda (noto'g'ri parol, server
    ishlamasa, foydalanuvchi topilmasa) False qaytaradi - hech qachon
    exception ko'tarmaydi (login oqimini to'xtatmaslik uchun).
    """
    if not is_ldap_configured():
        logger.warning("LDAP_SERVER sozlanmagan - LDAP autentifikatsiya o'tkazib yuborildi")
        return False
    if not password:
        return False  # bo'sh parol bilan anonim bind'ga yo'l qo'ymaslik

    if LDAP_AUTH_METHOD == "search_bind":
        return _search_bind(username, password)
    return _direct_bind(username, password)
