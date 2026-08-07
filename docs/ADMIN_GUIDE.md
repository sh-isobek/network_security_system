# Administrator Guide

Ushbu qo'llanma tizim administratorlari uchun — kundalik boshqaruv,
foydalanuvchi/rol boshqaruvi, monitoring va nosozliklarni bartaraf
etish bo'yicha.

## 1. Arxitektura qisqacha

Tizim mustaqil "engine" jarayonlaridan iborat, barchasi umumiy
ma'lumotlar bazasi (PostgreSQL/SQLite) orqali muvofiqlashadi:

```
[Kerio DHCP] [Windows DNS] [Switch/UniFi] [Suricata] [Snort] [Zeek]
        │           │              │           │        │      │
        └───────────┴──────────────┴───────────┴────────┴──────┘
                              │
                    [Syslog Collector / Readers]
                              │
                       [Parser Engine] ──► devices, events
                              │
              [File Analysis Engine] ──► hash tekshiruv
                              │
               [Deep Scan Engine] ──► YARA/ClamAV/makro
                              │
                    [MITRE Tagging Engine]
                              │
                    [UEBA Engine] ──► anomaliya, risk score
                              │
                  [Response Engine] ──► UniFi/Switch bloklash
                              │
              [Notification Engine] ──► Email/Telegram
                              │
                      [Web Dashboard] ◄── Administrator
```

To'liq tafsilot: `CLAUDE.md` va loyiha ildizidagi `docs_*_SETUP.md`
fayllariga qarang.

## 2. Xizmatlarni ishga tushirish/to'xtatish

**Docker Compose** (tavsiya etiladi):
```bash
docker compose up -d                      # barcha asosiy xizmatlar
docker compose --profile queue up -d      # + RabbitMQ navbat rejimi
docker compose --profile grafana up -d    # + Grafana
docker compose ps                          # holatni ko'rish
docker compose logs -f <xizmat-nomi>      # loglarni kuzatish
docker compose restart <xizmat-nomi>      # qayta ishga tushirish
```

**Kubernetes**: `docs_KUBERNETES_SETUP.md`ga qarang.

## 3. Xavfsizlik sozlamalari (birinchi o'rnatishda majburiy)

**Shifrlash kaliti** (MFA maxfiy kalitlari bazada shifrlangan saqlanishi uchun):
```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
# natijani .env fayliga ENCRYPTION_KEY=... qilib qo'shing
```
Agar `ENCRYPTION_KEY` sozlanmasa, tizim ishlashda davom etadi, lekin
MFA maxfiy kalitlari **ochiq matnda** saqlanadi (log'da ogohlantirish
chiqadi) - production'da bu albatta sozlanishi SHART.

**API Token'lar** (agentlar uchun, umumiy `AGENT_API_KEY` o'rniga
tavsiya etiladi):
```bash
python -m api.token_manager --create "ACCOUNTING-PC agent" --expires-days 365
```
Batafsil: `API_GUIDE.md`.

## 4. Foydalanuvchi va rol boshqaruvi (RBAC)

3 rol: `admin` (to'liq huquq), `analyst` (ko'rish + alert tasdiqlash),
`viewer` (faqat ko'rish).

**Yangi foydalanuvchi yaratish**:
```bash
python -m dashboard.create_user --username jdoe --password 'KuchliParol123!' --role analyst
```

**LDAP orqali** (parol markazda saqlanmaydi):
```bash
python -m dashboard.create_user --username jdoe --password placeholder --role viewer --auth-source ldap
```

Dashboard'da `/users` sahifasi orqali ham (faqat admin) foydalanuvchi
qo'shish/faolsizlantirish mumkin.

**MFA**: har bir foydalanuvchi o'zi `/mfa/setup` orqali yoqadi
(QR-kodni Google/Microsoft Authenticator bilan skanerlab). Admin
boshqa foydalanuvchi uchun majburiy qilib qo'ya olmaydi (hozircha) -
bu kelajakdagi kengaytirish sifatida qoldirilgan.

## 5. Monitoring va kundalik nazorat

- **Dashboard** (`/`) — umumiy holat: critical/high alertlar soni,
  zararli fayllar, oxirgi 10 alert.
- **Alertlar** (`/alerts`) — barcha alertlar, severity bo'yicha
  filtrlash, MITRE texnika ko'rsatiladi.
- **Live Map** (`/live-map`) — real-vaqt tarmoq topologiyasi.
- **Audit Log** (`/audit`, faqat admin) — kim, qachon, nima qildi.
- **Grafana** (agar yoqilgan bo'lsa) — http://localhost:3000, batafsil
  trendlar va metrikalar.

**Kundalik tekshiruv ro'yxati**:
1. `/` sahifasida critical alertlar sonini tekshiring
2. Xabar berilmagan (`notified=false`) alertlar bor-yo'qligini
   tekshiring (agar bor bo'lsa, `notification_engine` ishlamayotgan
   bo'lishi mumkin)
3. `docker compose ps` orqali barcha xizmatlar "Up" holatida ekanini
   tasdiqlang
4. `/audit` orqali kutilmagan admin harakatlarini kuzating

## 6. Whitelist/Blacklist boshqaruvi

Muhim serverlar (1C, domen kontroller) whitelist'ga qo'shilishi
SHART, aks holda tasodifiy bloklanishi mumkin:

```python
from engine.seed_lists import seed
# engine/seed_lists.py faylini tahrirlab, WHITELIST_IPS ro'yxatiga qo'shing
```

Yangi zararli domen/hash qo'lda qo'shish:
```python
from db.database import get_session
from db.models import BlacklistEntry, HashBlacklist
s = get_session()
s.add(BlacklistEntry(value="evil-domain.com", source="manual", reason="SOC tomonidan qo'shildi"))
s.commit()
```

## 7. Backup

Kundalik avtomatik backup uchun cron (yoki K8s CronJob) sozlang:
```bash
0 2 * * * cd /path/to/project && python -m backup.backup_manager --backup
```

To'liq tafsilot: `DISASTER_RECOVERY_GUIDE.md`.

## 8. Nosozliklarni bartaraf etish (Troubleshooting)

| Muammo | Tekshirish | Yechim |
|---|---|---|
| Dashboard ochilmaydi | `docker compose logs dashboard` | `DATABASE_URL` to'g'riligini tekshiring |
| Alertlar kelmayapti | `docker compose logs parser_engine` | Syslog manba (Kerio/Snort) to'g'ri sozlanganini tekshiring |
| Email yuborilmayapti | `docker compose logs notification_engine` | `SMTP_*` sozlamalarini tekshiring |
| Fayl tekshirilmayapti | `docker compose logs file_analysis_engine` | `VT_API_KEY` yoki tarmoq ulanishini tekshiring |
| ClamAV eskirgan | `freshclam` loglarini tekshiring | `docs_SURICATA_SETUP.md`dagi cron sozlamasini tekshiring |
| Muvaffaqiyatsiz bloklash | `/alerts`da "action_taken" ustunini o'qing | Switch/UniFi ulanish sozlamalarini (`.env`) tekshiring |

Qo'shimcha: loyiha ildizidagi `run_full_test.py`ni ishga tushirib,
barcha komponentlar to'g'ri ishlayotganini tasdiqlashingiz mumkin:
```bash
python3 run_full_test.py
```
