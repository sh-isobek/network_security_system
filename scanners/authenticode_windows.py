"""
Windows Authenticode raqamli imzo TASDIQLASH - `Get-AuthenticodeSignature` (Windows'ning o'z
kripto-tizimi, WinVerifyTrust/CryptoAPI) orqali.

MUHIM FARQ (`scanners/pe_analyzer.py`ning "signed" bayrog'idan): u yerda faqat PE
sarlavhasidagi imzo MA'LUMOTI (data directory yozuvi) bor-yo'qligi tekshiriladi - bu hech
narsani ISBOTLAMAYDI (imzo soxta yoki fayl imzolangandan keyin o'zgartirilgan bo'lishi mumkin).
Bu modul esa Windows'ning o'zidan HAQIQIY tasdiqlashni so'raydi: sertifikat zanjiri ishonchli
ildizga (Microsoft) borib taqaladimi, VA fayl SHA256'i imzolash vaqtidagi bilan mos keladimi.

Foydalanuvchi so'rovi ("tekshiruv natijasi hech qachon noma'lum qolmasligi kerak"): agent endi
BARCHA disklarni kuzatgani uchun, ko'p Windows tizim fayli (Microsoft.PowerShell.*.dll,
System.*.dll va h.k.) hash-intel (VT/MalwareBazaar) bazasida UMUMAN yo'q - ular kam tarqalgan,
noyob fayl bo'lgani uchun "noma'lum" bo'lib qolar edi. Bunday fayllarning aksariyati Microsoft
tomonidan imzolangan - endi ular imzo orqali TO'G'RIDAN-TO'G'RI (tarmoqsiz, darhol) "toza,
tasdiqlangan" deb aniqlanadi.

BONUS (yangi zararli aniqlash yo'li): agar imzolangan fayl KEYINCHALIK o'zgartirilgan bo'lsa
(masalan zararli kod kiritilgan) - `Status` "HashMismatch" bo'ladi. Bu deyarli 100% aniq
zararlanish belgisi (soxta-pozitiv xavfi juda past) - qonuniy dastur hech qachon o'z-o'zidan
"imzolangan, lekin hash mos kelmaydi" holatiga tushmaydi.

Faqat Windows'da ishlaydi (`platform.system() != "Windows"` bo'lsa `None`).
"""
import logging
import platform
import re
import subprocess
from typing import Optional

logger = logging.getLogger("authenticode_windows")

# Ishonchli deb hisoblanadigan imzolovchilar (sertifikat Subject'idagi CN= qatorida qidiriladi).
# ATAYLAB QISQA VA KONSERVATIV: faqat OS ishlab chiqaruvchisi - boshqa (uchinchi tomon,
# hatto mashhur) dasturlar imzolangan bo'lsa ham, ular hali hash-intel/heuristik tekshiruvga
# muhtoj (imzoning o'zi "zararsiz" degani emas - imzolangan zararli dastur ham bo'lgan holatlar
# ma'lum, ayniqsa o'g'irlangan/soxta sertifikatlar bilan - shu sabab ro'yxat qat'iy tor tutiladi).
_TRUSTED_PUBLISHERS = (
    "microsoft windows",
    "microsoft corporation",
)

_TIMEOUT_SECONDS = 15


def verify_authenticode(filepath: str) -> Optional[dict]:
    """
    Qaytaradi:
        None - Windows emas, yoki PowerShell/tekshiruv muvaffaqiyatsiz (hech narsa isbotlanmadi -
               chaqiruvchi bu holatni "ma'lumot yo'q" deb, boshqa signallarga tayanishi kerak).
        {"status": "Valid"|"HashMismatch"|"NotSigned"|"NotTrusted"|"UnknownError"|...,
         "publisher": str|None, "trusted_publisher": bool}
    """
    if platform.system() != "Windows":
        return None
    try:
        # -LiteralPath: fayl nomida `[`/`*` kabi belgilar bo'lsa ham wildcard sifatida
        # talqin qilinmasligi uchun. Oddiy '|' bilan ajratilgan bitta qator qaytariladi -
        # ConvertTo-Json'ning SignerCertificate'dagi aylanma (circular) havolalar bilan bog'liq
        # xatolaridan (yoki juda chuqur/og'ir JSON'dan) qochish uchun ataylab shunday.
        script = (
            "$ErrorActionPreference = 'SilentlyContinue'; "
            "$s = Get-AuthenticodeSignature -LiteralPath $args[0]; "
            "Write-Output ($s.Status.ToString() + '|' + $s.SignerCertificate.Subject)"
        )
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script, filepath],
            capture_output=True, text=True, timeout=_TIMEOUT_SECONDS,
        )
        lines = [ln for ln in (result.stdout or "").splitlines() if ln.strip()]
        if not lines or "|" not in lines[-1]:
            return None
        status, _, publisher = lines[-1].partition("|")
        status = status.strip()
        publisher = publisher.strip() or None
        m = re.search(r"CN=([^,]+)", publisher or "")
        cn = m.group(1).strip().lower() if m else ""
        return {
            "status": status,
            "publisher": publisher,
            "trusted_publisher": status == "Valid" and any(t in cn for t in _TRUSTED_PUBLISHERS),
        }
    except (OSError, subprocess.SubprocessError) as exc:
        logger.debug(f"Authenticode tekshiruv muvaffaqiyatsiz ({filepath}): {exc}")
        return None
