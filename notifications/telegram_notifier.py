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
    lines = [
        f"🚨 *Xavfsizlik Ogohlantirishi* [{alert_data.get('severity', '').upper()}]",
        "",
        f"*Vaqt:* {alert_data.get('timestamp', '')}",
        f"*Qurilma:* {alert_data.get('hostname', 'Nomalum')}",
        f"*IP:* {alert_data.get('ip_address', 'Nomalum')}",
        f"*MAC:* {alert_data.get('mac_address', 'Nomalum')}",
        f"*Ulanish:* {alert_data.get('connection_type', 'Nomalum')}",
        f"*Tafsilot:* {alert_data.get('reason', '')}",
        f"*Chora:* {alert_data.get('action_taken', '')}",
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
        "parse_mode": "Markdown",
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
