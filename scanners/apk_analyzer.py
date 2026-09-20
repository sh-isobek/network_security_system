"""
Android paketi (APK) statik tahlili - binar AndroidManifest.xml (AXML) parseri.

Faqat standart kutubxona (zipfile, struct) - Endpoint Agent .exe'siga va serverga
bir xil qo'shiladi. Manifest matn qidiruvi EMAS, haqiqiy AXML tuzilmasi o'qiladi:
paket nomi, ruxsatlar, komponentlar (activity/service/receiver), intent-filter
harakatlari, launcher ikonasi bor-yo'qligi.

Ball tizimi (aniq, tushuntiriladigan): har bir xavfli belgi ball beradi va
topilma matni bilan qaytadi. Yuqori ball = zararli APK'larga xos KOMBINATSIYA
(masalan SMS o'qish+yuborish + accessibility + yashirin ikona). Bitta belgi
(masalan faqat REQUEST_INSTALL_PACKAGES - F-Droid kabi qonuniy ilovalarda bor)
zararli deb hisoblanmaydi.

HALOL CHEKLOV: bu statik tahlil; obfuskatsiya qilingan/shifrlangan manifest yoki
ruxsatlarni ish vaqtida so'raydigan zararli dasturni ushlamasligi mumkin (dinamik
tahlil/sandbox alohida qadam).
"""
import struct
import zipfile
from typing import Optional

_RES_STRING_POOL = 0x0001
_RES_XML = 0x0003
_RES_XML_START_ELEMENT = 0x0102
_RES_XML_END_ELEMENT = 0x0103

MANIFEST_LIMIT = 4 * 1024 * 1024

# permission -> (ball, tavsif)
_PERMISSION_SCORES = {
    "READ_SMS": (25, "SMS o'qish"),
    "RECEIVE_SMS": (25, "SMS qabul qilish"),
    "SEND_SMS": (20, "SMS yuborish"),
    "WRITE_SMS": (5, "SMS yozish"),
    "READ_CALL_LOG": (5, "qo'ng'iroqlar tarixini o'qish"),
    "READ_CONTACTS": (5, "kontaktlarni o'qish"),
    "RECORD_AUDIO": (5, "mikrofondan yozish"),
    "REQUEST_INSTALL_PACKAGES": (10, "boshqa ilovalarni o'rnatish"),
    "SYSTEM_ALERT_WINDOW": (15, "boshqa ilovalar ustiga ekran chiqarish (overlay)"),
    "BIND_DEVICE_ADMIN": (15, "qurilma administratori"),
    "BIND_ACCESSIBILITY_SERVICE": (30, "accessibility xizmati (ekranni boshqarish)"),
    "QUERY_ALL_PACKAGES": (5, "barcha o'rnatilgan ilovalar ro'yxati"),
}

_SMS_READ = {"READ_SMS", "RECEIVE_SMS"}


class _Axml:
    def __init__(self, data: bytes):
        self.data = data
        self.strings = []
        self.elements = []  # (name, {attr: value})

    def _read_string_pool(self, off: int, size: int):
        d = self.data
        string_count, _style_count, flags, strings_start, _styles_start = struct.unpack_from("<5I", d, off + 8)
        is_utf8 = bool(flags & 0x100)
        offsets = struct.unpack_from(f"<{string_count}I", d, off + 28)
        base = off + strings_start
        out = []
        for so in offsets:
            p = base + so
            try:
                if is_utf8:
                    n = d[p]; p += 1
                    if n & 0x80:
                        n = ((n & 0x7F) << 8) | d[p]; p += 1
                    bl = d[p]; p += 1
                    if bl & 0x80:
                        bl = ((bl & 0x7F) << 8) | d[p]; p += 1
                    out.append(d[p:p + bl].decode("utf-8", errors="replace"))
                else:
                    n = struct.unpack_from("<H", d, p)[0]; p += 2
                    if n & 0x8000:
                        n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", d, p)[0]; p += 2
                    out.append(d[p:p + n * 2].decode("utf-16-le", errors="replace"))
            except (IndexError, struct.error):
                out.append("")
        self.strings = out

    def _s(self, idx: int) -> str:
        return self.strings[idx] if 0 <= idx < len(self.strings) else ""

    def parse(self):
        d = self.data
        if len(d) < 8 or struct.unpack_from("<H", d, 0)[0] != _RES_XML:
            raise ValueError("AXML emas")
        pos = struct.unpack_from("<H", d, 2)[0]
        while pos + 8 <= len(d):
            ctype, hsize, size = struct.unpack_from("<HHI", d, pos)
            if size < 8:
                break
            if ctype == _RES_STRING_POOL:
                self._read_string_pool(pos, size)
            elif ctype == _RES_XML_START_ELEMENT:
                ext = pos + hsize
                _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from("<IIHHH", d, ext)
                attrs = {}
                ap = ext + attr_start
                for _ in range(attr_count):
                    _ans, aname, raw, _tsize, _res0, dtype, data = struct.unpack_from("<IIIHBBI", d, ap)
                    if raw != 0xFFFFFFFF:
                        val = self._s(raw)
                    elif dtype == 0x03:
                        val = self._s(data)
                    elif dtype == 0x12:
                        val = "true" if data else "false"
                    else:
                        val = str(data)
                    attrs[self._s(aname)] = val
                    ap += attr_size
                self.elements.append((self._s(name_idx), attrs))
            pos += size


def parse_manifest(manifest_bytes: bytes) -> dict:
    """Binar manifestni o'qib, tahlil uchun tuzilma qaytaradi."""
    ax = _Axml(manifest_bytes)
    ax.parse()

    info = {
        "package": "", "permissions": [], "receiver_actions": set(),
        "has_launcher": False, "accessibility_service": False, "activity_count": 0,
        "service_count": 0, "receiver_count": 0,
    }
    # intent-filter action/category qaysi komponentga tegishli ekanini kuzatamiz
    current = None
    for name, attrs in ax.elements:
        if name == "manifest":
            info["package"] = attrs.get("package", "")
        elif name == "uses-permission" or name == "uses-permission-sdk-23":
            perm = attrs.get("name", "")
            if perm:
                info["permissions"].append(perm)
        elif name in ("activity", "activity-alias"):
            info["activity_count"] += 1
            current = "activity"
        elif name == "service":
            info["service_count"] += 1
            current = "service"
            if attrs.get("permission", "").endswith("BIND_ACCESSIBILITY_SERVICE"):
                info["accessibility_service"] = True
        elif name == "receiver":
            info["receiver_count"] += 1
            current = "receiver"
        elif name == "action":
            a = attrs.get("name", "")
            if current == "receiver":
                info["receiver_actions"].add(a)
            if a == "android.accessibilityservice.AccessibilityService":
                info["accessibility_service"] = True
        elif name == "category" and attrs.get("name") == "android.intent.category.LAUNCHER":
            info["has_launcher"] = True
    return info


def analyze_apk(filepath: str) -> Optional[dict]:
    """
    APK bo'lmasa None. Aks holda:
    {"package", "permissions", "score": 0-100, "findings": [str], "verdict_hint":
     "malicious"|"suspicious", "risky": [qisqa ruxsat nomlari]}

    verdict_hint: ball >= 80 - zararli APK'larga xos kombinatsiya ("malicious");
    aks holda "suspicious" (kompyuterda APK topilishining o'zi odatiy emas).
    """
    try:
        with zipfile.ZipFile(filepath) as zf:
            if "AndroidManifest.xml" not in zf.namelist():
                return None
            raw = zf.read("AndroidManifest.xml")[:MANIFEST_LIMIT]
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError, NotImplementedError):
        return None

    try:
        info = parse_manifest(raw)
    except (ValueError, struct.error, IndexError):
        # Manifest o'qib bo'lmadi (buzilgan/obfuskatsiya qilingan) - o'zi shubhali
        return {"package": "", "permissions": [], "score": 55, "risky": [],
                "verdict_hint": "suspicious",
                "findings": ["APK manifesti standart AXML sifatida o'qib bo'lmadi (buzilgan yoki yashirilgan)"]}

    short = {p.rsplit(".", 1)[-1] for p in info["permissions"]}
    risky = sorted(short & set(_PERMISSION_SCORES))
    findings = []
    score = 40  # APK'ning kompyuterda topilishi - asosiy ball
    findings.append("Android paketi (APK) kompyuterda topildi" + (f" - paket: {info['package']}" if info["package"] else ""))

    for perm in risky:
        pts, desc = _PERMISSION_SCORES[perm]
        score += pts
    if risky:
        findings.append("Xavfli ruxsatlar: " + ", ".join(f"{p} ({_PERMISSION_SCORES[p][1]})" for p in risky))

    sms_read = bool(short & _SMS_READ)
    if info["accessibility_service"]:
        if "BIND_ACCESSIBILITY_SERVICE" not in risky:
            score += 30
        findings.append("Accessibility xizmati e'lon qilingan (ekranni o'qish/boshqarish)")
    if "android.provider.Telephony.SMS_RECEIVED" in info["receiver_actions"]:
        score += 15
        findings.append("SMS_RECEIVED qabul qiluvchisi bor (kiruvchi SMS'larni ushlaydi)")
    if "android.intent.action.BOOT_COMPLETED" in info["receiver_actions"]:
        score += 5
        findings.append("Telefon yoqilganda o'zi ishga tushadi (BOOT_COMPLETED)")
    if not info["has_launcher"]:
        score += 10
        findings.append("Launcher ikonasi yo'q (ilova menyuda ko'rinmaydi - yashirin ishlashi mumkin)")

    # Kombinatsiya bonuslari (aniq zararli profil): SMS o'qish + yuborish, va
    # boshqarish vositasi (accessibility/overlay/device-admin)
    if sms_read and "SEND_SMS" in short:
        score += 10
        findings.append("KOMBINATSIYA: SMS o'qish va yuborish birga")
    if (sms_read or "SEND_SMS" in short) and (info["accessibility_service"] or "SYSTEM_ALERT_WINDOW" in short or "BIND_DEVICE_ADMIN" in short):
        score += 10
        findings.append("KOMBINATSIYA: SMS ruxsati + ekranni boshqarish vositasi")

    score = min(100, score)
    return {
        "package": info["package"], "permissions": info["permissions"], "risky": risky,
        "score": score, "findings": findings,
        "verdict_hint": "malicious" if score >= 80 else "suspicious",
    }
