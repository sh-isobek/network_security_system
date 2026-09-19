"""
Kunlik davomat hisoboti - Telegram va Email orqali avtomatik yuborish.

Har kuni bir marta (standart: mahalliy vaqt bilan ertalab, `ATTENDANCE_
REPORT_HOUR_LOCAL`) KECHAGI kunning kechikish/kelmaslik ro'yxatini
hisoblab, Telegram guruhiga va HR emaillariga yuboradi. `attn_daily_
report_log` orqali BIR KUNGA BIR MARTA yuborilishi ta'minlanadi (loop
qayta-qayta ishga tushsa ham takroriy xabar yubormaydi).

MUHIM (loyihaning o'z tajribasidan olingan saboq - CLAUDE.md'da
hujjatlashtirilgan Telegram xatosi): Telegram xabari HECH QACHON
`parse_mode="Markdown"` bilan yuborilmaydi - xodim ismida/bo'limida
uchrashi mumkin bo'lgan `[`, `_`, `*` kabi belgilar "can't parse
entities" xatosiga olib kelib, BUTUN xabarni yo'qotishi mumkin edi.
Bu yerda ataylab oddiy matn ishlatiladi.

Ishga tushirish:
    python -m attendance.report_engine            # kecha uchun, bir marta
    python -m attendance.report_engine --date 2026-09-16
    python -m attendance.report_engine --loop
"""
import argparse
import logging
import os
import smtplib
import sys
import time
from datetime import date, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import requests

from config.settings import LOG_LEVEL, TIMEZONE_OFFSET_HOURS, ATTENDANCE_REPORT_HOUR_LOCAL
from attendance.database import get_session
from attendance.models import DailyReportLog, utcnow
from attendance.stats import late_and_absent_for_date

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("attendance.report_engine")

REPORT_LOOP_CHECK_INTERVAL_SECONDS = 300  # 5 daqiqada bir "hozir hisobot vaqtimi?" tekshiradi


def _local_now():
    return utcnow() + timedelta(hours=TIMEZONE_OFFSET_HOURS)


def build_report_text(session, work_date: date) -> str:
    late, absent = late_and_absent_for_date(session, work_date)

    lines = [
        f"Kunlik Davomat Hisoboti - {work_date.isoformat()}",
        "",
        f"Kechikkanlar soni: {len(late)}",
    ]
    for rec in late[:50]:
        name = rec.employee.full_name if rec.employee else f"#{rec.employee_id}"
        dept = f" ({rec.employee.department})" if rec.employee and rec.employee.department else ""
        lines.append(f"  - {name}{dept}: {rec.late_minutes} daqiqa kech")

    lines.append("")
    lines.append(f"Kelmaganlar soni: {len(absent)}")
    for rec in absent[:50]:
        name = rec.employee.full_name if rec.employee else f"#{rec.employee_id}"
        dept = f" ({rec.employee.department})" if rec.employee and rec.employee.department else ""
        lines.append(f"  - {name}{dept}")

    if not late and not absent:
        lines.append("")
        lines.append("Barcha xodimlar vaqtida keldi.")

    return "\n".join(lines)


def _send_telegram(text: str) -> bool:
    bot_token = os.getenv("ATTENDANCE_TELEGRAM_BOT_TOKEN") or os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("ATTENDANCE_TELEGRAM_CHAT_ID") or os.getenv("TELEGRAM_CHAT_ID", "")
    if not bot_token or not chat_id:
        logger.warning("ATTENDANCE_TELEGRAM_BOT_TOKEN/CHAT_ID sozlanmagan - Telegram hisoboti yuborilmadi")
        return False
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        resp = requests.post(url, json={"chat_id": chat_id, "text": text}, timeout=10)
        if resp.status_code == 200:
            return True
        logger.error(f"Telegram hisobot yuborishda xato: {resp.status_code} {resp.text}")
        return False
    except requests.RequestException as exc:
        logger.error(f"Telegram hisobot yuborishda tarmoq xatosi: {exc}")
        return False


def _send_email(subject: str, text: str) -> bool:
    recipients_raw = os.getenv("ATTENDANCE_REPORT_EMAILS") or os.getenv("ADMIN_EMAIL", "")
    recipients = [r.strip() for r in recipients_raw.split(",") if r.strip()]
    if not recipients:
        logger.warning("ATTENDANCE_REPORT_EMAILS/ADMIN_EMAIL sozlanmagan - email hisobot yuborilmadi")
        return False

    smtp_host = os.getenv("SMTP_HOST", "localhost")
    smtp_port = int(os.getenv("SMTP_PORT", "25"))
    smtp_username = os.getenv("SMTP_USERNAME", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    smtp_use_tls = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
    smtp_from = os.getenv("SMTP_FROM", "attendance@company.local")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = smtp_from
    msg["To"] = ", ".join(recipients)
    msg.attach(MIMEText(text, "plain", "utf-8"))

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            if smtp_use_tls:
                server.starttls()
            if smtp_username:
                server.login(smtp_username, smtp_password)
            server.sendmail(smtp_from, recipients, msg.as_string())
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error(f"Email hisobot yuborishda xato: {exc}")
        return False


def send_daily_report(work_date: date = None, force: bool = False) -> dict:
    """
    Berilgan kun (standart: mahalliy kechagi kun) uchun hisobotni
    tuzib, Telegram+Email orqali yuboradi. Bir kunga bir marta
    (force=True bo'lmasa) - `attn_daily_report_log` orqali tasdiqlanadi.
    """
    if work_date is None:
        work_date = (_local_now() - timedelta(days=1)).date()

    session = get_session()
    try:
        log_row = session.query(DailyReportLog).filter_by(report_date=work_date).first()
        if log_row and log_row.telegram_sent and log_row.email_sent and not force:
            return {"skipped": True, "reason": "allaqachon yuborilgan"}

        text = build_report_text(session, work_date)
        telegram_ok = _send_telegram(text)
        email_ok = _send_email(f"Kunlik Davomat Hisoboti - {work_date.isoformat()}", text)

        if not log_row:
            log_row = DailyReportLog(report_date=work_date)
            session.add(log_row)
        log_row.telegram_sent = log_row.telegram_sent or telegram_ok
        log_row.email_sent = log_row.email_sent or email_ok
        log_row.sent_at = utcnow()
        session.commit()

        logger.info(f"{work_date} hisoboti: telegram={telegram_ok}, email={email_ok}")
        return {"skipped": False, "telegram_sent": telegram_ok, "email_sent": email_ok, "text": text}
    finally:
        session.close()


def run_loop():
    """
    Har `REPORT_LOOP_CHECK_INTERVAL_SECONDS`da mahalliy vaqtni tekshiradi -
    `ATTENDANCE_REPORT_HOUR_LOCAL` soatiga yetganda (va shu kun uchun hali
    yuborilmagan bo'lsa) kechagi kun hisobotini yuboradi.
    """
    logger.info(f"Report engine ishga tushdi (har kuni soat {ATTENDANCE_REPORT_HOUR_LOCAL}:00 mahalliy vaqtda)")
    while True:
        now_local = _local_now()
        if now_local.hour == ATTENDANCE_REPORT_HOUR_LOCAL:
            send_daily_report()
        time.sleep(REPORT_LOOP_CHECK_INTERVAL_SECONDS)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kunlik davomat hisobotini yuborish")
    parser.add_argument("--date", type=str, default=None, help="YYYY-MM-DD (standart: kecha)")
    parser.add_argument("--loop", action="store_true")
    parser.add_argument("--force", action="store_true", help="Allaqachon yuborilgan bo'lsa ham qayta yuborish")
    args = parser.parse_args()

    if args.loop:
        run_loop()
    else:
        target = date.fromisoformat(args.date) if args.date else None
        result = send_daily_report(target, force=args.force)
        print(result)
