# Installation Guide

Bu hujjat butun tizimni noldan o'rnatishning **tavsiya etilgan
tartibini** ko'rsatadi. Har bir bosqich uchun batafsil yo'riqnoma
alohida faylda (loyiha ildizida, `docs_*_SETUP.md`).

## Talablar

- Docker + Docker Compose (yoki Kubernetes klasteri)
- PostgreSQL 16+ (Docker Compose orqali avtomatik keladi)
- Kamida 4 GB RAM, 20 GB disk (asosiy xizmatlar uchun)
- Tarmoq: SPAN port (Suricata/Snort uchun), SMTP server, LDAP server
  (agar ishlatilsa) kirishlariga ega bo'lishi

## Tavsiya etilgan o'rnatish tartibi

### 1-bosqich: Asosiy platforma

```bash
git clone https://github.com/sh-isobek/network_security_system.git
cd network_security_system
cp .env.example .env
# .env faylini oching, kamida quyidagilarni to'ldiring:
#   POSTGRES_PASSWORD, AGENT_API_KEY, DASHBOARD_SECRET_KEY
docker compose up -d
```

Tekshirish:
```bash
docker compose ps          # barchasi "Up" bo'lishi kerak
```

### 2-bosqich: Birinchi admin foydalanuvchi

```bash
docker compose exec dashboard python -m dashboard.create_user \
    --username admin --password 'KuchliParol123!' --role admin
```

Dashboard'ga kiring: http://localhost:8080

### 3-bosqich: Tarmoq log manbalarini ulash

Quyidagilarning har biri **alohida, ixtiyoriy** bosqich - kerakli
manbalarni tanlang:

| Manba | Yo'riqnoma | Nima uchun kerak |
|---|---|---|
| Kerio Control (DHCP) | Loyiha ildizidagi `docs_NXLOG_SETUP.md` (Kerio qismi) | IP-MAC-hostname bog'lash |
| Windows AD DNS | `docs_NXLOG_SETUP.md` | DNS so'rovlarini kuzatish |
| Suricata (asosiy IDS) | `docs_SURICATA_SETUP.md` | Fayl ekstraktsiyasi, tarmoq alertlari |
| Snort (qo'shimcha IDS) | `docs_SNORT_SETUP.md` | Qo'shimcha signatura qatlami |
| Zeek (tarmoq tahlili) | `docs_ZEEK_SETUP.md` | Boy metadata (conn/dns/files log) |
| ClamAV | `docs_SURICATA_SETUP.md` (ClamAV qismi) | Antivirus qatlami |

### 4-bosqich: Endpoint Agentlar

| Platforma | Yo'riqnoma |
|---|---|
| Windows | `docs_WINDOWS_AGENT_SETUP.md` |
| Linux | `docs_LINUX_AGENT_SETUP.md` |
| macOS | `docs_MAC_AGENT_SETUP.md` |

### 5-bosqich: Bildirishnoma va autentifikatsiya

`.env` faylida:
```
NOTIFY_CHANNELS=email,telegram
SMTP_HOST=...
TELEGRAM_BOT_TOKEN=...
LDAP_SERVER=...   # agar Active Directory orqali login kerak bo'lsa
```

### 6-bosqich (ixtiyoriy): Yuqori yuklama va monitoring

```bash
docker compose --profile queue up -d      # RabbitMQ navbat rejimi
docker compose --profile grafana up -d    # Grafana dashboard
```

### 7-bosqich (ixtiyoriy): Kubernetes'ga o'tish

Agar Docker Compose o'rniga Kubernetes ishlatmoqchi bo'lsangiz:
`docs_KUBERNETES_SETUP.md`ga qarang. **Muhim**: avval Docker image'ni
build va push qilishingiz kerak (qo'llanmada tushuntirilgan).

## O'rnatishni tekshirish

```bash
docker compose exec dashboard python3 run_full_test.py
```

Barcha testlar "✅" bilan tugashi kerak (ba'zi testlar tashqi
xizmatlar - masalan Snort/LDAP - o'rnatilmagan bo'lsa avtomatik
o'tkazib yuboriladi, bu normal).

## Keyingi qadamlar

- `ADMIN_GUIDE.md` — kundalik boshqaruv
- `USER_GUIDE.md` — Dashboard'dan foydalanish
- `DISASTER_RECOVERY_GUIDE.md` — backup va halokatdan tiklash rejasi
