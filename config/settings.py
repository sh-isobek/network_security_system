"""
Markaziy konfiguratsiya fayli.
Barcha modullar shu yerdan sozlamalarni oladi — hech qaysi modulda
IP, port yoki parol hardcode qilinmaydi.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# ---- Tarmoq diapazoni ----
NETWORK_RANGE_START = os.getenv("NETWORK_RANGE_START", "172.16.0.11")
NETWORK_RANGE_END = os.getenv("NETWORK_RANGE_END", "172.16.3.254")

# ---- Syslog qabul qiluvchi ----
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
# Diqqat: 514-port <1024 bo'lgani uchun Linux'da root yoki
# CAP_NET_BIND_SERVICE huquqi kerak. Test uchun 5140 tavsiya etiladi.
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5140"))

# ---- Ma'lumotlar bazasi ----
# Boshlang'ich bosqichda SQLite, keyinchalik PostgreSQL'ga ko'chirish mumkin
# (DATABASE_URL ni o'zgartirish kifoya, kod o'zgarmaydi - SQLAlchemy tufayli)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./logs/security_system.db")

# ---- Log fayl (xom loglarni saqlash uchun, audit maqsadida) ----
RAW_LOG_FILE = os.getenv("RAW_LOG_FILE", "./logs/raw_syslog.log")

# ---- Umumiy dastur sozlamalari ----
APP_NAME = "Network Security Monitoring System"
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# ---- Dashboard'da ko'rsatiladigan mahalliy vaqt zonasi ----
# MUHIM: bazada BARCHA vaqt belgilari (timestamp) UTC formatida saqlanadi
# (turli manbalardan - Suricata, Windows Event Log, syslog - kelayotgan
# loglarni to'g'ri solishtirish/korrelyatsiya qilish uchun bu standart
# amaliyot). Bu sozlama FAQAT Dashboard'da FOYDALANUVCHIGA ko'rsatilganda
# qo'llaniladi - baza ichidagi qiymatlarga ta'sir qilmaydi.
# Misol: Toshkent (UTC+5) uchun TIMEZONE_OFFSET_HOURS=5
TIMEZONE_OFFSET_HOURS = int(os.getenv("TIMEZONE_OFFSET_HOURS", "5"))

# ---- 5-bosqich: Avtomatik javob choralari ----
# "dry_run" - hech narsani real o'zgartirmaydi, faqat loglaydi (DEFAULT, xavfsiz)
# "live"    - haqiqiy uskunalarga ulanadi (faqat ongli ravishda yoqilsin)
RESPONSE_MODE = os.getenv("RESPONSE_MODE", "dry_run")

# Qurilma darajasidagi karantin uchun qaysi adapter ishlatilsin (live rejimda)
# variantlar: "unifi" | "switch_snmp"
QUARANTINE_BACKEND = os.getenv("QUARANTINE_BACKEND", "unifi")

# Alohida firewall/gateway orqali IP bloklash uchun backend (live rejimda)
# variantlar: "mikrotik" | "opnsense" | "linux_nftables"
FIREWALL_BACKEND = os.getenv("FIREWALL_BACKEND", "mikrotik")

# ---- Dashboard: qurilma "tarmoqqa ulangan/ulanmagan" holati ----
# `Device.last_seen` (DHCP/DNS/Suricata trafigi, ARP/ICMP skanerlash yoki
# UniFi sinxronizatsiyasidan yangilanadi) shu vaqtdan ko'proq eski bo'lsa,
# qurilma Dashboard'da "Offlayn/Uzilgan" deb ko'rsatiladi. Standart 60
# daqiqa - bu network_discovery scheduler'ning standart 1 soatlik
# skanerlash intervaliga (`--interval 3600`) mos keladi.
DEVICE_OFFLINE_THRESHOLD_MINUTES = int(os.getenv("DEVICE_OFFLINE_THRESHOLD_MINUTES", "60"))

# ---- Endpoint Agent "online/offline" holati (Dashboard) ----
# Bu YUQORIDAGI DEVICE_OFFLINE_THRESHOLD_MINUTES'dan FARQLI - o'sha
# BARCHA qurilmalar (DHCP/DNS/Suricata/ARP/UniFi orqali ko'rilgan) uchun
# "tarmoqqa ulanganmi" degan savolga javob beradi, bu esa FAQAT agent
# o'rnatilgan qurilmalar uchun "Endpoint Agent hali ham xabar
# yuboryaptimi" degan alohida, ko'proq real-vaqtli savolga javob
# beradi (agent HEARTBEAT_INTERVAL_SECONDS, standart 5 daqiqada bir
# marta "tirikman" xabarini yuboradi). Standart 15 daqiqa = ~3
# heartbeat davri (bitta/ikkita ketma-ket heartbeat yo'qolishi -
# masalan vaqtinchalik tarmoq uzilishi - jim ravishda "offline" deb
# belgilab qo'ymasligi uchun bir oz zaxira bilan).
AGENT_ONLINE_THRESHOLD_MINUTES = int(os.getenv("AGENT_ONLINE_THRESHOLD_MINUTES", "15"))

