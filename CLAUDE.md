# Tarmoq Xavfsizligi Monitoring Tizimi — Loyiha Xotirasi

Bu fayl Claude Code tomonidan har bir sessiya boshida avtomatik o'qiladi.
Loyiha claude.ai chat orqali bosqichma-bosqich qurilgan; bu yerda butun
tarix, arxitektura qarorlari va joriy holat qisqacha yozilgan - shunda
yangi sessiya noldan boshlamaydi.

## Loyiha nima

Korxona tarmog'ini (172.16.0.0/22) monitoring qiladigan, tahdidlarni
aniqlaydigan, avtomatik javob beradigan va hisobot beruvchi xavfsizlik
tizimi. Dastlabki TZ oddiy ichki skript sifatida boshlangan, keyin
foydalanuvchi uni "korporativ SIEM/XDR platformasi" darajasidagi TZ'ga
(24 bo'lim: Kafka, Kubernetes, AI/UEBA, RBAC/MFA va h.k.) kengaytirdi.
**Qaror: hammasini bir yo'la qurish real emas - har safar bitta aniq,
to'liq test qilinadigan bosqichni tanlab, uni oxirigacha qurib, keyin
navbatdagisiga o'tish strategiyasi tanlandi.**

## MUHIM QOIDA: har doim real test bilan tasdiqlash

Bu loyihaning eng muhim printsipi: **hech qanday kod "ishlashi kerak"
degan taxmin bilan qoldirilmaydi**. Har bir yangi modul:
1. Real ma'lumot/jarayon/server bilan qo'lda sinaladi (mock emas, haqiqiy).
2. `run_full_test.py`ga alohida `check(...)` bandi sifatida qo'shiladi.
3. Test **ham SQLite'da, ham PostgreSQL'da** ishga tushiriladi
   (`export DATABASE_URL="postgresql://postgres:testpass123@localhost:5432/<db>"`).

Yangi sessiya boshlaganda birinchi qadam:
```bash
cd network-security-system
pip install -r requirements.txt --break-system-packages
python3 run_full_test.py
```
Agar 17/17 "✅ BARCHA TESTLAR MUVAFFAQIYATLI O'TDI" chiqmasa - avval
buni tuzatish kerak, keyingi bosqichga o'tilmaydi.

## Arxitektura (yakuniy qarorlar)

- **Kerio Control** — FAQAT DHCP manba sifatida ishlatiladi (foydalanuvchi
  talabi). DNS — alohida Windows AD DNS Server'dan (NXLog orqali
  forward qilinadi). Bloklash — Kerio orqali EMAS, alohida
  firewall/gateway (hali tanlanmagan) yoki switch/UniFi orqali.
- **Baza**: SQLAlchemy ORM, `DATABASE_URL` orqali SQLite (dev) yoki
  PostgreSQL (production/Docker) - kod o'zgarmaydi.
- **Enginelar** (`engine/*.py`) — barchasi bir xil pattern: `run_once()`
  (bitta tsikl) + `run_loop(interval)` (doimiy ishlash uchun CLI).
  Navbat-asosida ishlaydi (`checked=False`/`notified=False` kabi
  bayroqlar) - shuning uchun bir nechta nusxada parallel ishga tushirish
  xavfsiz (SQL orqali tabiiy tanlash).
- **Agentlar**: Windows/Linux/macOS uchun BITTA umumiy yadro
  (`agent_core/`) - `windows_agent/`, `linux_agent/`, `mac_agent/` faqat
  yupqa kirish nuqtalari (standart papkalar + OS-specific service
  wrapper). Kodni ikki marta yozmaslik uchun shunday qilingan.
- **Dashboard**: Flask + Jinja2 (server-rendered, React/build vositasi
  yo'q). RBAC: `flask-login` + 3 rol (admin/analyst/viewer).

## Bosqichlar tarixi (0 dan hozirgacha)

| # | Nima qurildi | Holat |
|---|---|---|
| 0 | Syslog collector (UDP) + DB skeleti | ✅ test qilingan |
| 1 | Parser (Kerio DHCP/Connection, Windows DNS JSON) | ✅ |
| 2-3 | Suricata integratsiyasi (eve.json reader) + hash tekshiruv (local/VT/MalwareBazaar) | ✅ |
| 4 | Deep scan: YARA + Office makro (oletools) + ZIP rekursiya | ✅ |
| 5 | Response engine: UniFi/Switch(SNMP) adapterlari, pluggable arxitektura | ✅ (switch_port CAM-table orqali avtomatik aniqlash hali YO'Q - bilib turing) |
| 6 | Windows Endpoint Agent + markaziy API (Flask) | ✅ to'liq E2E (fayl o'chirish, jarayon o'ldirish) |
| 7 | Email/Telegram bildirishnoma | ✅ real SMTP bilan test qilingan |
| — | ClamAV (clamscan CLI, YARA'ga qo'shimcha) | ✅ |
| — | MITRE ATT&CK avtomatik belgilash (`intel/mitre_attack.py`) | ✅ |
| — | Web Dashboard (keyinroq RBAC bilan almashtirildi) | ✅ |
| — | Docker Compose (11 xizmat) + PostgreSQL | ✅ (Docker o'zi sandbox'da yo'q, lekin Postgres'da to'liq test qilingan) |
| — | CSV/JSON hisobotlar (`reports/report_generator.py`) | ✅ |
| — | Linux Agent (`agent_core/` orqali) | ✅ to'liq E2E |
| — | Mac Agent | ✅ kod yozilgan, launchd, LEKIN haqiqiy macOS'da SINALMAGAN |
| — | RBAC (User jadvali, flask-login, 3 rol, acknowledge huquqi) | ✅ |
| — | PDF/Excel hisobotlar (`reports/report_generator.py`: `export_summary_pdf`, `export_alerts_excel`) | ✅ real fayl + LibreOffice recalc bilan tasdiqlangan |
| — | Snort integratsiyasi (`collectors/snort_reader.py`) | ✅ HAQIQIY Snort binary bilan (pcap orqali, scapy sintetik paketlar) |
| — | Zeek integratsiyasi (`collectors/zeek_reader.py`) | ⚠️ kod yozilgan, sxemaga mos sintetik JSON bilan test qilingan, LEKIN haqiqiy Zeek binary bilan SINALMAGAN (OBS/Docker Hub domenlari ruxsat etilmagan) |
| — | MFA/TOTP (`dashboard/mfa.py`) | ✅ real TOTP algoritmi bilan (QR-kod, to'liq login oqimi) |
| — | LDAP Login (`dashboard/ldap_auth.py`) | ✅ HAQIQIY OpenLDAP server bilan (o'rnatilgan, sozlangan, real bind orqali) |
| — | RabbitMQ Queue (`messaging/`, `collectors/syslog_server_queued.py`, `engine/queue_ingest_worker.py`) | ✅ HAQIQIY RabbitMQ broker bilan, to'liq UDP->Queue->Worker->DB zanjiri test qilingan |
| — | UEBA / AI (`ueba/anomaly_detection.py`, `engine/ueba_engine.py`) | ✅ Statistik (Z-score) anomaliya aniqlash + Risk Score, real sintetik "normal+buzilgan" trafik bilan (soxta-pozitivsiz) test qilingan |

**Joriy: 24/24 test o'tadi (`run_full_test.py`).**

## UEBA/AI haqida muhim izoh

`ueba/anomaly_detection.py` **chuqur o'rganish (deep learning) emas** -
klassik Z-score (3-sigma) statistik anomaliya aniqlash. Bu ataylab
tanlangan: (1) natija tushuntirib bo'ladigan ("nega anomaliya" aniq
javob beriladi), (2) kam ma'lumot bilan ham ishonchli ishlaydi,
(3) "AI" deb signature-based qoidalarni sotmaslik printsipiga amal
qilingan (bu `CLAUDE.md`ning ilgari yozilgan qismida ham aytilgan edi).
Agar chinakam ML (masalan Isolation Forest, LSTM) kerak bo'lsa, bu
alohida, kattaroq ish - hozirgi statistik yondashuv puxta poydevor
sifatida xizmat qiladi (bir xil `Baseline`/`AnomalyResult` interfeysi
saqlanadi, faqat `compute_baseline()`/`detect_anomaly()` ichki
mantiqi almashtiriladi).

## GitHub va CI

Loyiha `https://github.com/sh-isobek/network_security_system` manziliga
push qilingan (`main` branch). Har bir push'da GitHub Actions
(`.github/workflows/full-test.yml`) `run_full_test.py`ni **ham
SQLite'da, ham PostgreSQL'da** avtomatik ishga tushiradi (haqiqiy
GitHub'ning `ubuntu-latest` runner'ida, mening lokal sandbox'imdan
mustaqil muhitda).

**MUHIM (haqiqiy topilgan va tuzatilgan xato):** CI birinchi push'da
`sqlite3.OperationalError: unable to open database file` bilan
muvaffaqiyatsiz bo'ldi - sabab: `logs/` papkasi Git'da bo'sh bo'lgani
uchun (Git bo'sh papkalarni saqlamaydi) yangi `git clone`da umuman
mavjud emas edi. Bu mening doimiy ishlab turgan lokal sandbox'imda
"yashiringan" edi, chunki papka u yerda fizik jihatdan doim mavjud edi.
Tuzatildi: `db/database.py`ga `_ensure_sqlite_dir_exists()` qo'shildi
(SQLite yo'lidan papkani avtomatik yaratadi) + `logs/.gitkeep` qo'shildi.

**MUHIM (ikkinchi topilgan va tuzatilgan xato, Snort/Zeek bosqichida):**
`apt-get install snort` GitHub'ning haqiqiy `systemd`li runner'ida
muvaffaqiyatsiz bo'ldi - sabab: Snort'ning post-install skripti
xizmatni **avtomatik ishga tushirishga** urinadi, bu esa runner'da
muvaffaqiyatsiz tugaydi (interfeys yo'q/noto'g'ri sozlangan). Bu ham
mening lokal sandbox'imda "yashiringan" edi - u yerda `policy-rc.d`
xizmatlarni avtomatik ishga tushirishni allaqachon bloklagani uchun
(konteynerlarning standart xatti-harakati). Tuzatildi: CI workflow'iga
paket o'rnatishdan OLDIN `policy-rc.d` skripti qo'shildi (xizmatlar
avtomatik ishga tushishini rad etadi - Docker konteynerlaridagi kabi).

**MUHIM (uchinchi topilgan va tuzatilgan xato, MFA/LDAP bosqichida):**
Real OpenLDAP (`slapd`) bilan test qilishda CI'da `Permission denied
(13)` xatoligi - sabab: Ubuntu'ning **AppArmor** profili `slapd`ni
faqat ma'lum papkalardan (odatda `/etc/ldap/**`, `/var/lib/ldap/**`)
konfiguratsiya o'qishga cheklaydi, bizning test esa `/tmp/` ostida
maxsus config ishlatgan. Bu ham lokal sandbox'da (AppArmor bu yerda
faol emas) yashiringan edi. Muhim diagnostika usuli: `slapd -Tt -f
<conf>` orqali sinxron xato xabarini olish - bu darhol aniq sababni
ko'rsatdi ("Permission denied"), taxmin qilishga hojat qolmadi.
Birinchi urinish (`aa-complain` faqat slapd uchun) yetarli bo'lmadi,
ikkinchi urinishda butun AppArmor subsystemini CI runner'ida o'chirish
(`systemctl stop apparmor` + `aa-teardown`) muammoni hal qildi.

**Umumiy xulosa (3 marta tasdiqlandi)**: yangi katta o'zgarish
qilinganda, `git clone` qilib, toza muhitda test qilish kerak - lokal
ishlagan narsa har doim ham CI/production'da ishlayvermaydi. Ayniqsa
"konteyner ichida systemd/AppArmor/service-management cheklangan" kabi
sandbox-specific xususiyatlar tashqi (haqiqiy VM) muhitda boshqacha
xatti-harakat qilishi mumkin. Muvaffaqiyatsiz CI'ni tuzatishda TAXMIN
QILMASLIK kerak - avval aniq diagnostika (xato xabarini to'liq
chiqarish, kerak bo'lsa vositaning o'z "test/dry-run" rejimidan
foydalanish) qo'shib, keyin tuzatish kerak.

## GitHub holati (joriy)

Repo: https://github.com/sh-isobek/network_security_system (`main` branch)
GitHub Actions CI: ✅ yashil (`.github/workflows/full-test.yml`),
har push'da SQLite va PostgreSQL'da 22 bosqichli to'liq testni
haqiqiy GitHub runner'ida ishga tushiradi.

Push qilish uchun avval foydalanuvchidan yangi Personal Access Token
so'rash kerak (fine-grained, "Contents: Read and write" + "Workflows:
Read and write" ruxsatlari bilan, aniq shu repo uchun) - oldingi
token'lar sessiyada saqlanmaydi.

## Bilib turish kerak bo'lgan cheklovlar (halol)

- **Docker**: `docker-compose.yml`/`Dockerfile` yozilgan, YAML tekshirilgan,
  lekin `docker compose up` haqiqiy Docker'da HECH QACHON ishga
  tushirilmagan (sandbox'da Docker yo'q). Ishonch darajasi yuqori,
  chunki butun tizim PostgreSQL'da (Compose'dagi bilan bir xil DB) to'liq
  sinalgan.
- **Mac Agent**: kod to'g'ri (agent_core allaqachon Darwin-mos), lekin
  haqiqiy macOS'da hech qachon ishga tushirilmagan.
- **Switch port avtomatik aniqlash**: `response/switch_adapter.py` port
  raqamini `TargetDevice.switch_port` orqali kutadi, lekin buni MAC
  manzildan avtomatik topish (CAM-table SNMP so'rovi) hali yozilmagan -
  demak `cable` ulanishli qurilmalar uchun response_engine hozircha
  "adapter topilmadi" deb to'g'ri xabar beradi, lekin real bloklamaydi.
- **VirusTotal/MalwareBazaar/Telegram API**: sandbox tarmoq siyosati
  bu domenlarni bloklaydi (`api.telegram.org`, `virustotal.com` va h.k.
  ruxsat etilgan domenlar ro'yxatida yo'q) - kod to'g'ri yozilgan va
  xatoni to'g'ri boshqaradi (test qilingan), lekin haqiqiy tashqi
  javobni hech qachon olmagan.
- **pysnmp** Python 3.12 bilan mos kelmaydi (eskirgan loyiha) - shuning
  uchun `switch_adapter.py` `pysnmp` o'rniga `snmpset`/`snmpget` CLI
  (net-snmp) orqali ishlaydi.

## Keyingi navbatdagi (foydalanuvchi so'ragan, hali qurilmagan)

Ustuvorlik tartibi bo'yicha emas - foydalanuvchi tanlaganicha:
- **Kubernetes** — `docker-compose.yml`dagi 14 xizmatni K8s
  Deployment/Service manifestlariga aylantirish. (Yagona qolgan yangi
  TZ bo'limi - MFA/LDAP, Kafka/RabbitMQ, AI/UEBA, Zeek/Snort barchasi
  qurilgan.)

## MUHIM: sandbox'da "ghost" fayllar haqida

Bir necha marta shu loyihada sandbox sessiyasi qulagan/tiklangan paytda,
oldingi (chatda ko'rinmagan) urinishlardan qolgan fayllar diskda topilgan
- masalan `actions/` papkasi (ishlatilmagan, o'chirilgan) va
  `reports/report_generator.py` ichidagi `export_summary_pdf`/
  `export_alerts_excel` funksiyalari (sifatli, ishlatilgan holda topildi).
**Yangi narsa qurishdan oldin har doim mavjud fayllarni tekshiring**
(`grep -n "^def \|^class "` yoki `view` orqali) - ehtimol allaqachon
yozilgan bo'lishi mumkin, ikki marta ish qilmang.

## Ishga tushirish (tezkor eslatma)

```bash
# Kutubxonalar
pip install -r requirements.txt --break-system-packages

# OS darajasidagi bog'liqliklar (Suricata/ClamAV/SNMP uchun)
apt install clamav clamav-freshclam snmp

# Test
python3 run_full_test.py

# Xizmatlarni alohida ishga tushirish (misol)
python -m collectors.syslog_server
python -m engine.parser_engine --loop
python -m dashboard.app          # http://localhost:8080
python -m dashboard.create_user --username admin --password '...' --role admin
python -m reports.report_generator --period-days 7 --format csv,json,pdf,excel
```

To'liq hujjatlar: `README.md` va `docs_*.md` fayllarga qarang (har bir
katta qism uchun alohida yo'riqnoma bor: SURICATA, WINDOWS_AGENT,
LINUX_AGENT, MAC_AGENT, DOCKER_DEPLOYMENT, NXLOG_SETUP).
