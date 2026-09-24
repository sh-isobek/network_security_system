"""
Agentni "qayta ulanishga urinish" oqimi (Dashboard tugmasi -> watchdog -> natija).

Server qurilmaga HECH QACHON o'zi ulanmaydi (agent so'raydi, server javob beradi), shuning
uchun oqim `Device.agent_restart_status` orqali kuzatiladi:

    pending    - admin tugmani bosdi, watchdog hali olmagan
    picked_up  - watchdog so'rovni oldi (xizmatni qayta ishga tushirmoqda)
    restarted  - watchdog xizmat "Running" ekanini xabar qildi, agent heartbeat'i kutilmoqda
    success    - agent heartbeat'i keldi (haqiqatan ulandi)
    failed     - AGENT_RESTART_DEADLINE_SECONDS (standart 60s) ichida ulanmadi -> Alert (high)

Bir kompyuter Dashboard'da bir nechta `Device` qatori bo'lib qolishi mumkin (hostname turli
manbalardan - Kerio/Ruijie/agent - turlicha yoziladi: "ISOBEK", "Isobek a4:d7",
"sph-027.synergypharm.org"), shuning uchun kompyuterni hostname'ning QISQA nomi, MAC yoki IP
bo'yicha aniqlaymiz.
"""
import os
import re
from datetime import timedelta

from db.models import Alert, Device, utcnow

DEADLINE_SECONDS = int(os.getenv("AGENT_RESTART_DEADLINE_SECONDS", "60"))
IN_PROGRESS = ("pending", "picked_up", "restarted")


def short_name(hostname):
    return (hostname or "").strip().lower().split(".")[0] or None


def norm_mac(mac):
    digits = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    return digits if len(digits) == 12 else None


def _matches(dev, hostname=None, ips=(), macs=()):
    if hostname and short_name(dev.hostname) == short_name(hostname):
        return True
    if dev.ip_address and dev.ip_address in set(ips or ()):
        return True
    dm = norm_mac(dev.mac_address)
    return bool(dm and dm in {norm_mac(m) for m in (macs or ()) if norm_mac(m)})


def request_restart(session, device, username, now=None):
    """Tugma bosilganda. Allaqachon jarayonda bo'lsa False qaytaradi (qayta-qayta so'rov yubormaslik uchun)."""
    now = now or utcnow()
    if device.agent_restart_status in IN_PROGRESS:
        return False
    device.agent_restart_status = "pending"
    device.agent_restart_message = None
    device.agent_restart_requested_at = now
    device.agent_restart_requested_by = username
    device.agent_restart_picked_up_at = None
    device.agent_restart_finished_at = None
    return True


def pick_up(session, hostname, ips=(), macs=(), now=None):
    """Watchdog so'raganda: shu kompyuterga tegishli 'pending' qatorlarni 'picked_up'ga o'tkazadi."""
    now = now or utcnow()
    rows = [d for d in session.query(Device).filter(Device.agent_restart_status == "pending").all()
            if _matches(d, hostname, ips, macs)]
    for d in rows:
        d.agent_restart_status = "picked_up"
        d.agent_restart_picked_up_at = now
    return rows


def report(session, hostname, success, message, ips=(), macs=(), now=None):
    """Watchdog xizmatni qayta ishga tushirish natijasini xabar qiladi."""
    now = now or utcnow()
    rows = [d for d in session.query(Device).filter(Device.agent_restart_status == "picked_up").all()
            if _matches(d, hostname, ips, macs)]
    for d in rows:
        if success:
            d.agent_restart_status = "restarted"
            d.agent_restart_message = (message or "Xizmat ishga tushirildi, heartbeat kutilmoqda")[:500]
        else:
            _fail(session, d, f"Watchdog xizmatni ishga tushira olmadi: {message}", now)
    return rows


def mark_heartbeat(session, hostname, ip=None, mac=None, now=None):
    """Agent heartbeat yubordi -> shu kompyuterning jarayondagi so'rovlari 'success'."""
    now = now or utcnow()
    n = 0
    for d in session.query(Device).filter(Device.agent_restart_status.in_(IN_PROGRESS)).all():
        if _matches(d, hostname, [ip] if ip else (), [mac] if mac else ()):
            d.agent_restart_status = "success"
            d.agent_restart_finished_at = now
            d.agent_restart_message = "Agent qayta ulandi"
            n += 1
    return n


def _fail(session, dev, message, now):
    dev.agent_restart_status = "failed"
    dev.agent_restart_finished_at = now
    dev.agent_restart_message = message[:500]
    name = dev.hostname or dev.ip_address
    session.add(Alert(
        device_id=dev.id, severity="high", timestamp=now,
        reason=f"Agent qayta ulanmadi: {name} ({dev.ip_address}) - {message}",
        action_taken=f"Admin ({dev.agent_restart_requested_by or '?'}) qayta ulanishni so'ragan; "
                     f"{DEADLINE_SECONDS} soniya ichida ulanmadi",
        notified=False, network_response_done=True,
    ))


_TIMEOUT_MESSAGES = {
    "pending": ("{s} soniya ichida javob bermadi: qurilmada watchdog ishlamayapti (agent 1.0.21+ o'rnatilmagan), "
                "kompyuter o'chiq yoki tarmoqdan tashqarida"),
    "picked_up": "Watchdog so'rovni oldi, lekin xizmatni qayta ishga tushirish natijasi {s} soniyada kelmadi",
    "restarted": ("Xizmat ishga tushdi, lekin {s} soniya ichida serverga heartbeat kelmadi "
                  "(server manzili/API kalit yoki tarmoq muammosi)"),
}


def expire_overdue(session, now=None):
    """Muddati o'tgan (DEADLINE_SECONDS) jarayondagi so'rovlarni 'failed' qiladi va Alert yaratadi."""
    now = now or utcnow()
    cutoff = now - timedelta(seconds=DEADLINE_SECONDS)
    failed = []
    for d in session.query(Device).filter(Device.agent_restart_status.in_(IN_PROGRESS),
                                          Device.agent_restart_requested_at <= cutoff).all():
        _fail(session, d, _TIMEOUT_MESSAGES[d.agent_restart_status].format(s=DEADLINE_SECONDS), now)
        failed.append(d)
    return failed
