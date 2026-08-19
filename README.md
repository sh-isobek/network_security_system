# Tarmoq Xavfsizligi Monitoring Tizimi — 0-bosqich (Poydevor)

Bu bosqichda quyidagilar quriladi va test qilinadi:
- Ma'lumotlar bazasi strukturasi (SQLAlchemy ORM)
- UDP Syslog qabul qiluvchi server

## Loyiha strukturasi

```
network-security-system/
├── config/
│   └── settings.py          # Barcha sozlamalar shu yerda (IP, port, DB URL)
├── db/
│   ├── models.py            # Jadval strukturalari (devices, events, alerts, ...)
│   └── database.py          # Baza sessiyasi
├── collectors/
│   └── syslog_server.py     # UDP syslog qabul qiluvchi
├── logs/                    # Xom loglar va SQLite bazasi shu yerda saqlanadi
├── requirements.txt
└── .env.example
```

## O'rnatish

```bash
cd network-security-system
pip install -r requirements.txt
cp .env.example .env
```

`.env` faylini oching va kerak bo'lsa qiymatlarni o'zgartiring.

## Ishga tushirish (test rejimi, 5140-port)

```bash
python -m collectors.syslog_server
```

Server ishga tushgach, quyidagi kabi log ko'rasiz:
```
[INFO] Syslog server ishga tushmoqda: 0.0.0.0:5140
```

## Test qilish

Boshqa terminalda test paketi yuboring:

```bash
python3 -c "
import socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
msg = b'<134>Jul 30 13:01:58 KERIO-GW Connection: SRC=172.16.1.45 DST=8.8.8.8 DPT=443 PROTO=TCP ACTION=Permit'
sock.sendto(msg, ('127.0.0.1', 5140))
"
```

Natijani tekshiring:
- `logs/raw_syslog.log` faylida yangi qator paydo bo'ladi
- `logs/security_system.db` bazasidagi `raw_logs` jadvalida yangi yozuv paydo bo'ladi

## Production'da 514-portga o'tish

`.env` faylida:
```
SYSLOG_PORT=514
```

514-port <1024 bo'lgani uchun Linux'da maxsus huquq kerak. Systemd orqali
ishga tushirsangiz, service faylida quyidagini qo'shing:

```ini
AmbientCapabilities=CAP_NET_BIND_SERVICE
```

Yoki oddiyroq yo'l — root sifatida ishga tushirish (tavsiya etilmaydi) yoki
`setcap` orqali python binaryga huquq berish:

```bash
sudo setcap 'cap_net_bind_service=+ep' $(which python3)
```

## Kerio Control tomonida sozlash

Kerio Control > Configuration > Advanced Options > Logging bo'limida:
- **Syslog server**: ushbu Python server ishlayotgan mashina IP manzili
- **Port**: 514 (yoki test uchun 5140)
- **Protocol**: UDP
- Yuboriladigan loglar: faqat **DHCP** bilan bog'liq event'lar (chunki
  loyiha talabiga ko'ra Kerio faqat DHCP manba sifatida ishlatiladi).

## Keyingi bosqich

Bazaga tushayotgan `raw_logs` yozuvlarini o'qib, ulardan IP/MAC/hostname/
dest/port ajratib oladigan **Parser** moduli (1-bosqich: DNS Monitoring bilan
birga) yoziladi.

## Bildirishnomalar (7-bosqich)

`.env` fayliga quyidagilarni qo'shing:

```
NOTIFY_CHANNELS=email,telegram

SMTP_HOST=smtp.company.local
SMTP_PORT=587
SMTP_USE_TLS=true
SMTP_USERNAME=security-alerts@company.local
SMTP_PASSWORD=...
SMTP_FROM=security-alerts@company.local
ADMIN_EMAIL=admin@company.local

TELEGRAM_BOT_TOKEN=...   # @BotFather orqali olinadi
TELEGRAM_CHAT_ID=...     # https://api.telegram.org/bot<TOKEN>/getUpdates orqali aniqlanadi
```

Ishga tushirish:
```bash
python -m engine.notification_engine --loop
```

## Kengaytmalar (yangi TZ asosida)

| Kengaytma | Papka | Tavsif |
|---|---|---|
| MITRE ATT&CK | `intel/`, `engine/mitre_tagging_engine.py` | Alertlarni MITRE texnika/taktika bilan avtomatik belgilaydi |
| Web Dashboard | `dashboard/` | `python -m dashboard.app` — http://localhost:8080 (Basic Auth) |
| Docker Compose | `Dockerfile`, `docker-compose.yml` | `docs_DOCKER_DEPLOYMENT.md`ga qarang. PostgreSQL'da to'liq sinovdan o'tkazilgan |
| CSV/JSON hisobotlar | `reports/report_generator.py` | `python -m reports.report_generator --period-days 7 --format csv,json` yoki Dashboard'dan yuklab olish |
| ClamAV | `scanners/clamav_scanner.py` | YARA'ga qo'shimcha antivirus qatlami (`docs_SURICATA_SETUP.md`) |
| Linux Agent | `agent_core/`, `linux_agent/` | Windows Agent bilan bir xil yadro (`agent_core/`) - `docs_LINUX_AGENT_SETUP.md`ga qarang. To'liq real E2E test bilan tasdiqlangan (Linux sandbox'da) |
| RabbitMQ Queue | `messaging/`, `collectors/syslog_server_queued.py` | Yuqori yuklama uchun navbat-asosli kollektor. `docker compose --profile queue up` orqali yoqiladi |
| UEBA / AI | `ueba/`, `engine/ueba_engine.py` | Statistik (Z-score) anomaliya aniqlash + Risk Score. `python -m engine.ueba_engine --all` |
| Kubernetes | `k8s/*.yaml` | 24 resurs, haqiqiy k3s klasterida to'liq sinalgan (`docs_KUBERNETES_SETUP.md`) |
| Audit Log | `dashboard/audit.py` | Dashboard'dagi barcha muhim harakatlar qayd etiladi (`/audit`, faqat admin) |
| Backup/Restore | `backup/backup_manager.py` | `python -m backup.backup_manager --backup` / `--restore FILE` / `--list` |
| Live Map | `/live-map`, `/api/topology` | Interaktiv real-vaqt tarmoq topologiyasi (vis-network) |
| Grafana | `grafana/dashboards/security-overview.json` | 8 panelli dashboard, SQL so'rovlar real bazaga qarshi tekshirilgan (`docs_GRAFANA_LIVEMAP.md`) |
| Encryption at Rest | `crypto/field_encryption.py` | MFA maxfiy kaliti bazada shifrlangan saqlanadi (Fernet) |
| API Token boshqaruvi | `api/token_manager.py` | `python -m api.token_manager --create NAME` / `--list` / `--revoke ID`, yoki `/api-tokens` |
| Network Discovery | `network_discovery/` | ARP/ICMP/TCP/SNMP/LLDP/CDP/AD/UniFi/Kerio - `docs_NETWORK_DISCOVERY.md` |
| Auto-Deploy (SSH+GitHub) | `deploy/auto_deploy.sh` | GitHub'dan avtomatik yangilanish - `docs_DEPLOYMENT_SSH_AUTOUPDATE.md` |
| Windows Agent GPO + Coverage | `deploy/windows_agent_gpo/`, `network_discovery/agent_coverage.py` | AD orqali avtomatik tarqatish + qamrov hisoboti (`/agent-coverage`) - `docs_WINDOWS_AGENT_SETUP.md` (5-bo'lim) |
| Windows Agent .exe build | `.github/workflows/build-windows-agent.yml` | GitHub'ning haqiqiy Windows runner'ida `.exe` quradi - Actions → Build Windows Agent → Artifacts |
| Web Activity (saytlar tarixi) | `db.models.WebAccessLog`, `collectors/zeek_reader.py` | Zeek HTTP/SSL/DNS loglaridan avtomatik - `/web-activity`, `docs_WEB_ACTIVITY_INTEGRATION.md` |
| Xavfsiz Karantin | `agent_core/quarantine.py`, `engine/quarantine.py` | Tasdiqlangan zararli fayllar SHA256 tekshiruvi bilan karantinga olinadi - `docs_MALWARE_RESPONSE.md` |
| Mac Agent | `mac_agent/` | Xuddi shu yadro, launchd konfiguratsiyasi - `docs_MAC_AGENT_SETUP.md`ga qarang (kod yozilgan, lekin haqiqiy macOS'da sinalmagan) |
| RBAC | `dashboard/auth.py`, `dashboard/create_user.py` | 3 rol (admin/analyst/viewer), sessiya-asosli login, parollar xeshlangan. Boshlang'ich foydalanuvchi: `python -m dashboard.create_user --username admin --password '...' --role admin` |

## Rasmiy hujjatlar

| Hujjat | Kim uchun |
|---|---|
| [`docs/INSTALLATION_GUIDE.md`](docs/INSTALLATION_GUIDE.md) | O'rnatuvchi muhandis - noldan to'liq o'rnatish yo'l xaritasi |
| [`docs/ADMIN_GUIDE.md`](docs/ADMIN_GUIDE.md) | Tizim administratori - kundalik boshqaruv, RBAC, nosozliklarni bartaraf etish |
| [`docs/USER_GUIDE.md`](docs/USER_GUIDE.md) | Xavfsizlik analitiklari - Dashboard'dan foydalanish |
| [`docs/API_GUIDE.md`](docs/API_GUIDE.md) | Integratsiya muhandislari - Agent API va Dashboard API |
| [`docs/DISASTER_RECOVERY_GUIDE.md`](docs/DISASTER_RECOVERY_GUIDE.md) | Tizim administratori - backup, halokatdan tiklash rejasi |

## Ma'lumotlar bazasi jadvallari (qisqacha)

| Jadval | Vazifasi |
|---|---|
| `raw_logs` | Har bir kelgan syslog xabarining xom nusxasi |
| `devices` | IP/MAC/hostname bog'langan qurilmalar ro'yxati |
| `events` | Parsing qilingan tarmoq hodisalari (source→dest, port, protokol) |
| `file_events` | Suricata aniqlagan fayl transferlari (hash, verdict, deep-scan natijasi) |
| `hash_blacklist` | Ma'lum zararli fayl hash'lari |
| `alerts` | Xavfli deb topilgan hodisalar va ko'rilgan choralar |
| `whitelist` | Hech qachon bloklanmaydigan IP/domenlar (1C serverlar va h.k.) |
| `blacklist` | Ma'lum zararli IP/domenlar |
