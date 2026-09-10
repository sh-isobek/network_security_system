"""
Telegram Notifier - 7-bosqich.

Telegram Bot API orqali admin guruhiga/shaxsiy chatga xabar yuboradi.
Format TZ'dagi namunaga mos:

    Xavfsizlik Ogohlantirishi
    Computer: ACCOUNTING-PC
    User/IP: 172.16.1.45
    File/Domen: invoice.exe
    Threat: Trojan.GenericKD
    Action: Fayl bloklandi

Bot yaratish: @BotFather orqali /newbot, keyin chat_id'ni aniqlash uchun
botga xabar yuboring va https://api.telegram.org/bot<TOKEN>/getUpdates
orqali chat_id'ni ko'ring.
"""
import logging
import os

import requests

logger = logging.getLogger("telegram_notifier")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_API_URL = "https://api.telegram.org/bot{token}/sendMessage"


def _build_message(alert_data: dict) -> str:
    """
    MUHIM (real production xatosi tuzatilgan): avval `parse_mode:
    "Markdown"` bilan yuborilardi, va `reason`/severity kabi DINAMIK
    maydonlar HECH QANDAY escape qilinmasdan to'g'ridan-to'g'ri
    interpolatsiya qilinardi. Telegram'ning legacy Markdown formati
    `_`, `*`, `` ` ``, `[` belgilarini maxsus deb hisoblaydi - Alert
    matnida bular deyarli har doim uchraydi (masalan `[Trojan.Generic]`
    kabi threat nomi, yoki `[LEXICAL_PHISHING]` yorlig'i, yoki
    `invoice_final.exe` kabi pastki chiziqli fayl nomi) - bittasi
    ochiq qolsa ("juftlashmagan `[`" kabi), Telegram butun xabarni
    "can't parse entities" bilan RAD ETARDI.

    Bu xato ilgari HECH QACHON sinalmagan edi - sandbox tarmoq
    siyosati `api.telegram.org`ni bloklaganligi sababli (CLAUDE.md'da
    ilgari ham hujjatlashtirilgan), kod "to'g'ri yozilgan" deb
    hisoblangan, lekin haqiqiy Telegram API'ga birinchi marta real
    xabar yuborilganda (production'da) darhol ochilib qoldi - deyarli
    HAR BIR alert uchun (chunki reason matnida deyarli har doim
    maxsus belgi bor), demak xabarnomalar amalda HECH QACHON
    yetkazilmagan.

    Tuzatish: `parse_mode` butunlay OLIB TASHLANDI (oddiy matn) - bu
    formatlashni yo'qotadi (qalin matn), lekin Alert matni QANDAY
    bo'lishidan qat'iy nazar HECH QACHON parslanish xatosi bilan rad
    etilmasligini kafolatlaydi - bu xavfsizlik xabarnomasi uchun
    "chiroyli, lekin yetib bormaydi"dan ko'ra ancha muhim.
    """
    lines = [
        f"🚨 Xavfsizlik Ogohlantirishi [{alert_data.get('severity', '').upper()}]",
        "",
        f"Vaqt: {alert_data.get('timestamp', '')}",
        f"Qurilma: {alert_data.get('hostname', 'Nomalum')}",
        f"IP: {alert_data.get('ip_address', 'Nomalum')}",
        f"MAC: {alert_data.get('mac_address', 'Nomalum')}",
        f"Ulanish: {alert_data.get('connection_type', 'Nomalum')}",
        f"Tafsilot: {alert_data.get('reason', '')}",
        f"Chora: {alert_data.get('action_taken', '')}",
    ]
    return "\n".join(lines)


def send_alert_telegram(alert_data: dict, timeout: int = 10) -> bool:
    """
    Xabarnoma yuboradi. Muvaffaqiyatli bo'lsa True, xatolik bo'lsa False
    qaytaradi (tizimni to'xtatmaslik uchun exception ko'tarilmaydi).
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        logger.warning("TELEGRAM_BOT_TOKEN/CHAT_ID sozlanmagan - xabar yuborilmadi")
        return False

    url = TELEGRAM_API_URL.format(token=TELEGRAM_BOT_TOKEN)
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": _build_message(alert_data),
        # MUHIM: `parse_mode` ATAYLAB YO'Q - yuqoridagi `_build_message()`
        # docstring'iga qarang (real production xatosi tuzatilgan:
        # Markdown parslash reason matnidagi oddiy belgilardan
        # (`[`/`_`/`*`) tez-tez buzilib, xabarnoma HECH QACHON
        # yetib bormasdi).
    }

    try:
        resp = requests.post(url, json=payload, timeout=timeout)
        if resp.status_code == 200:
            logger.info("Telegram xabar yuborildi")
            return True
        logger.error(f"Telegram API xatoligi: HTTP {resp.status_code} - {resp.text[:200]}")
        return False
    except requests.RequestException as exc:
        logger.error(f"Telegram'ga ulanib bo'lmadi: {exc}")
        return False
