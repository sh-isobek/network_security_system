"""
Hikvision ISAPI mijozi - DS-K1T342MFWX (Face ID terminali) uchun.

MUHIM, HALOL CHEKLOV: bu sessiya ishlagan sandbox tarmoq siyosati
tashqi/lokal-bo'lmagan IP manzillarga (jumladan foydalanuvchi bergan
`194.93.24.92:88`) chiqishni ruxsat bermaydi (`curl` bilan tekshirilgan -
ulanish 8 soniyada timeout bo'ldi, DNS/routing xatosi emas). Shuning
uchun bu modul HAQIQIY qurilmaga hech qachon ulanmasdan, faqat rasmiy
Hikvision ISAPI hujjatlaridagi (va real production terminallaridan
kuzatilgan, keng tarqalgan) JSON formatiga mos qilib yozilgan - va
`attendance/run_attendance_test.py`da LOKAL, soxta ISAPI serveri (aynan
shu formatni takrorlaydigan) orqali real HTTP so'rov/javob bilan test
qilinadi (loyihaning UniFi/Ruijie integratsiyalarida ham ishlatilgan
pattern - CLAUDE.md'ga qarang). Haqiqiy qurilmaga qarshi bir martalik
tasdiqlash foydalanuvchi tarmog'idan turib (masalan shu qurilma bilan
bir xil LAN'dagi production serverda) qilinishi kerak.

ISAPI autentifikatsiya: standart holatda HTTP Digest Auth (Hikvision
terminallarining odatiy sozlamasi).

Asosiy endpoint'lar:
  - GET  /ISAPI/System/deviceInfo?format=json
  - POST /ISAPI/AccessControl/AcsEvent?format=json  (davomat hodisalarini
    vaqt oralig'i bo'yicha qidirish, sahifalab - `searchResultPosition`)
"""
import logging
import os
import uuid
from datetime import datetime, timedelta, timezone

import requests
from requests.auth import HTTPDigestAuth

logger = logging.getLogger("attendance.hikvision_client")

MAX_RESULTS_PER_PAGE = 30
MAX_PAGES_SAFETY = 500  # cheksiz tsiklga tushib qolmaslik uchun xavfsizlik chegarasi


class HikvisionAuthError(Exception):
    pass


class HikvisionClient:
    def __init__(self, host: str, port: int, username: str, password: str,
                 use_https: bool = False, timeout: int = 15, verify_ssl: bool = False):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        scheme = "https" if use_https else "http"
        self.base_url = f"{scheme}://{host}:{port}"
        self._auth = HTTPDigestAuth(username, password)

    def _request(self, method: str, path: str, **kwargs):
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(
                method, url, auth=self._auth, timeout=self.timeout,
                verify=self.verify_ssl,
                proxies={"http": None, "https": None},  # ichki qurilma - tashqi proksiga muhtoj emas
                **kwargs,
            )
        except requests.RequestException as exc:
            logger.error(f"Hikvision so'rovi muvaffaqiyatsiz ({url}): {exc}")
            raise
        if resp.status_code == 401:
            raise HikvisionAuthError(f"Hikvision autentifikatsiyasi rad etildi: {url}")
        resp.raise_for_status()
        return resp

    def get_device_info(self) -> dict:
        """Qurilma modeli/seriya raqami/firmware versiyasini qaytaradi (ulanishni tekshirish uchun)."""
        resp = self._request("GET", "/ISAPI/System/deviceInfo?format=json")
        return resp.json().get("DeviceInfo", {})

    def search_acs_events(self, start_time: datetime, end_time: datetime,
                           max_pages: int = MAX_PAGES_SAFETY):
        """
        `start_time`/`end_time` oralig'idagi BARCHA AccessControl (kirish
        nazorati/yuz tanish) hodisalarini sahifalab, generator sifatida
        qaytaradi (har bir element - device'ning xom `InfoList` yozuvi).

        `start_time`/`end_time` naive UTC datetime deb qabul qilinadi -
        ISAPI so'roviga esa ISO8601 + UTC offset (+00:00) formatida
        yuboriladi (device o'zi buni o'z mahalliy vaqt zonasiga o'giradi -
        rasmiy hujjat bo'yicha bu ISAPI'ning kutgan formati).
        """
        search_id = str(uuid.uuid4())
        position = 0
        page = 0
        while page < max_pages:
            body = {
                "AcsEventCond": {
                    "searchID": search_id,
                    "searchResultPosition": position,
                    "maxResults": MAX_RESULTS_PER_PAGE,
                    "major": 0,   # 0 = barcha major toifalar
                    "minor": 0,   # 0 = barcha minor toifalar
                    "startTime": _to_isapi_time(start_time),
                    "endTime": _to_isapi_time(end_time),
                }
            }
            resp = self._request(
                "POST", "/ISAPI/AccessControl/AcsEvent?format=json", json=body,
            )
            data = resp.json().get("AcsEvent", {})
            info_list = data.get("InfoList", []) or []
            for item in info_list:
                yield item

            status = data.get("responseStatusStrg", "")
            num_matches = len(info_list)
            page += 1
            if status != "MORE" or num_matches == 0:
                break
            position += num_matches


def _to_isapi_time(dt: datetime) -> str:
    """Naive UTC datetime -> ISAPI'ning kutgan ISO8601+offset formati."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"


def get_client_from_env() -> HikvisionClient:
    """
    Muhit o'zgaruvchilarini HAR CHAQIRUVDA dinamik o'qiydi (modul import
    vaqtida EMAS) - bu loyihada bir necha marta uchragan "muzlab qolgan
    muhit o'zgaruvchisi" xato turkumini oldini oladi (CLAUDE.md'da
    hujjatlashtirilgan: ad_discovery.py, UniFi/Ruijie tuzatishlari).

    Standart host/port foydalanuvchi bergan haqiqiy qurilma manziliga
    (194.93.24.92:88) mos - lekin `.env` orqali istalgan vaqt qayta
    sozlanishi mumkin.
    """
    host = os.getenv("HIKVISION_HOST", "194.93.24.92")
    port = int(os.getenv("HIKVISION_PORT", "88"))
    username = os.getenv("HIKVISION_USERNAME", "admin")
    password = os.getenv("HIKVISION_PASSWORD", "")
    use_https = os.getenv("HIKVISION_USE_HTTPS", "false").lower() == "true"
    if not password:
        raise RuntimeError(
            "HIKVISION_PASSWORD sozlanmagan - Face ID terminaliga ulanib bo'lmaydi "
            "(.env fayliga qo'shing)"
        )
    return HikvisionClient(host, port, username, password, use_https=use_https)
