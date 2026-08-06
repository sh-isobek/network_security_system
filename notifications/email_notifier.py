"""
Email Notifier - 7-bosqich.

TZ talabiga to'liq mos formatlangan xat yuboradi:
    - Hodisa vaqti: YYYY-MM-DD HH:MM:SS
    - Qurilma ma'lumotlari: Hostname, IP, MAC
    - Ulanish tarmog'i: Wi-Fi yoki Kabel
    - Xavfli so'rov: qaysi sayt/IP va port
    - Ko'rilgan chora

`smtplib` va `email.mime` standart kutubxonalari ishlatiladi (TZ'da
aniq shu kutubxonalar ko'rsatilgan).
"""
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger("email_notifier")

SMTP_HOST = os.getenv("SMTP_HOST", "localhost")
SMTP_PORT = int(os.getenv("SMTP_PORT", "25"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "false").lower() == "true"
SMTP_FROM = os.getenv("SMTP_FROM", "security-alerts@company.local")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "")


def _build_html_body(alert_data: dict) -> str:
    """
    alert_data kalitlari: timestamp, hostname, ip_address, mac_address,
    connection_type, target, reason, action_taken, severity
    """
    severity_colors = {
        "critical": "#c0392b", "high": "#e67e22", "medium": "#f1c40f", "low": "#95a5a6",
    }
    color = severity_colors.get(alert_data.get("severity", "medium"), "#95a5a6")

    return f"""
    <html>
    <body style="font-family: Arial, sans-serif; color: #2c3e50;">
        <div style="border-left: 5px solid {color}; padding: 15px; background: #f9f9f9;">
            <h2 style="color: {color}; margin-top: 0;">
                Xavfsizlik Ogohlantirishi [{alert_data.get('severity', '').upper()}]
            </h2>
            <table style="border-collapse: collapse; width: 100%;">
                <tr><td style="padding: 6px; font-weight: bold;">Hodisa vaqti:</td>
                    <td style="padding: 6px;">{alert_data.get('timestamp', '')}</td></tr>
                <tr><td style="padding: 6px; font-weight: bold;">Qurilma:</td>
                    <td style="padding: 6px;">{alert_data.get('hostname', 'Nomalum')}</td></tr>
                <tr><td style="padding: 6px; font-weight: bold;">IP manzil:</td>
                    <td style="padding: 6px;">{alert_data.get('ip_address', 'Nomalum')}</td></tr>
                <tr><td style="padding: 6px; font-weight: bold;">MAC manzil:</td>
                    <td style="padding: 6px;">{alert_data.get('mac_address', 'Nomalum')}</td></tr>
                <tr><td style="padding: 6px; font-weight: bold;">Ulanish tarmog'i:</td>
                    <td style="padding: 6px;">{alert_data.get('connection_type', 'Nomalum')}</td></tr>
                <tr><td style="padding: 6px; font-weight: bold;">Tafsilot:</td>
                    <td style="padding: 6px;">{alert_data.get('reason', '')}</td></tr>
                <tr><td style="padding: 6px; font-weight: bold;">Ko'rilgan chora:</td>
                    <td style="padding: 6px;">{alert_data.get('action_taken', '')}</td></tr>
            </table>
        </div>
    </body>
    </html>
    """


def send_alert_email(alert_data: dict) -> bool:
    """
    Xabarnoma yuboradi. Muvaffaqiyatli bo'lsa True, xatolik bo'lsa False
    qaytaradi (tizimni to'xtatmaslik uchun exception ko'tarilmaydi).
    """
    if not ADMIN_EMAIL:
        logger.warning("ADMIN_EMAIL sozlanmagan - email yuborilmadi")
        return False

    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"[XAVFSIZLIK] {alert_data.get('severity', '').upper()} - {alert_data.get('hostname', 'Nomalum qurilma')}"
    msg["From"] = SMTP_FROM
    msg["To"] = ADMIN_EMAIL
    msg.attach(MIMEText(_build_html_body(alert_data), "html", "utf-8"))

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, [ADMIN_EMAIL], msg.as_string())
        logger.info(f"Email yuborildi: {ADMIN_EMAIL}")
        return True
    except (smtplib.SMTPException, OSError) as exc:
        logger.error(f"Email yuborishda xatolik: {exc}")
        return False
