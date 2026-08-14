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
| — | Kubernetes (`k8s/*.yaml`, 6 fayl, 24 resurs) | ✅✅ HAQIQIY k3s klasterida (v1.28, cgroup v1 muhitiga moslashtirilgan) to'liq sinaldi - control plane, Node, Pod scheduling, barcha 24 resurs server-side dry-run + real apply orqali tasdiqlangan. Faqat konteyner ijrosi (`docker.io` bloklangani sabab) sinalmagan |
| — | Audit Log (`dashboard/audit.py`) | ✅ Login/logout/acknowledge/user boshqaruvi/MFA/hisobot yuklab olish - barchasi qayd etiladi, RBAC bilan (`/audit`, faqat admin) |
| — | Backup/Restore (`backup/backup_manager.py`) | ✅ SQLite (sqlite3 backup API) va PostgreSQL (pg_dump/psql) - ikkalasi ham real "halokat→backup→tiklash" stsenariysi bilan test qilingan |
| — | Live Map (`/live-map`, `/api/topology`) | ✅ To'liq ishlaydi, real HTTP orqali test qilingan (vis-network, risk-score rangi, real ma'lumot) |
| — | Grafana (`grafana/dashboards/security-overview.json`) | ⚠️ Grafana'ning o'zi o'rnatilmagan (dl.grafana.com ruxsat etilmagan), LEKIN barcha 8 panel SQL so'rovi haqiqiy PostgreSQL'ga qarshi test qilingan va to'g'ri natija bergan |
| — | Rasmiy hujjatlar (`docs/ADMIN_GUIDE.md`, `USER_GUIDE.md`, `API_GUIDE.md`, `INSTALLATION_GUIDE.md`, `DISASTER_RECOVERY_GUIDE.md`) | ✅ Barcha 5 guide, ichki havolalar va CLI buyruqlari kod bilan solishtirib tekshirilgan |
| — | Encryption at Rest (`crypto/field_encryption.py`) | ✅ MFA maxfiy kaliti endi bazada shifrlangan saqlanadi (Fernet, kalit almashtirish qo'llab-quvvatlanadi). To'liq MFA login oqimi orqali (shifrlash→saqlash→ochish) real test qilingan |
| — | API Token boshqaruvi (`api/token_manager.py`) | ✅ Har bir agent uchun alohida, bekor qilinadigan, muddatli token (eski AGENT_API_KEY'ga qo'shimcha, orqaga moslik bilan). `/api-tokens` Dashboard sahifasi (RBAC bilan) |
| — | Network Discovery (`network_discovery/`, 14 modul) | ✅✅ HAQIQIY tarmoqda (ARP/ICMP/TCP/SNMP), HAQIQIY OpenLDAP'da (AD), HAQIQIY L2 send+capture bilan (LLDP/CDP) test qilingan - bu loyihadagi eng chuqur real-infratuzilma testi |

**Joriy: 41/41 test o'tadi (`run_full_test.py`).**

## Windows Agent AD-orqali avtomatlashtirish (foydalanuvchining production so'rovi)

Foydalanuvchi domenga a'zo ko'p Windows kompyuterlarga agentni qo'lda
o'rnatish o'rniga, **Active Directory GPO** orqali avtomatlashtirishni
so'radi.

Qurilgan:
- `deploy/windows_agent_gpo/Deploy-NetworkSecurityAgent.ps1` - GPO
  Startup Script (idempotent, versiya solishtiradi, SYSVOL'dan
  o'rnatadi). ⚠️ PowerShell bu sandbox'da yo'q - ijro sinalmagan
  (Zeek/Grafana kabi), lekin qavslar/tirnoq balansi qo'lda tekshirilgan.
- `api/server.py`ga `/api/v1/agent_heartbeat` endpoint (agent har
  5 daqiqada "tirikman" xabari yuboradi).
- `agent_core/agent.py`ga davriy heartbeat yuborish logikasi.
- `network_discovery/agent_coverage.py` - AD'dagi barcha kompyuterlar
  ro'yxatini heartbeat ma'lumoti bilan solishtirib, `covered`/`stale`/
  `missing` hisoboti chiqaradi. Dashboard'da `/agent-coverage`.

**Real test qilingan**: heartbeat mexanizmi to'liq real HTTP orqali;
Agent Coverage Report haqiqiy OpenLDAP (maxsus AD sxema bilan) va
haqiqiy heartbeat ma'lumoti bilan - barcha 3 holat (covered/stale/
missing) va case-insensitive hostname moslashtirish tasdiqlangan.

**Topilgan va tuzatilgan xato**: `ad_discovery.py` muhit
o'zgaruvchilarini modul darajasida (import paytida) o'qir edi - bu
loyihada bir necha marta uchragan tanish xato turkumi
(`field_encryption.py`da avval tuzatilgan). Funksiya ichida dinamik
o'qishga o'zgartirildi - bu ham `ad_discovery.py`dan foydalanuvchi
BOSHQA barcha joylarni (mavjud AD Discovery testi ham) to'g'irladi.

## Windows Agent .exe paketi - GitHub Actions'ning HAQIQIY Windows runner'ida qurilgan

Foydalanuvchi to'g'ri aniqladi: GPO orqali avtomatlashtirish uchun
avval `.exe`/`.ps1` o'rnatuvchi paket kerak edi, u yo'q edi (faqat
Python manba kodi bor edi).

Qurilgan:
- `windows_agent/build/NetworkSecurityAgent.spec` - PyInstaller spec,
  `service_wrapper.py`ni (agent.py emas - Windows Service sifatida
  ishlashi uchun) mustaqil `.exe`ga aylantiradi.
- `.github/workflows/build-windows-agent.yml` - **eng muhim yechim**:
  Linux sandbox'da Wine bilan emas, GitHub'ning **haqiqiy
  `windows-latest` runner'ida** `.exe`ni quradi va `--help` bilan
  ishga tushirilishini tasdiqlaydi. Bu loyihadagi eng chuqur real
  Windows-tomon testi.
- `deploy/windows_agent_gpo/Install-NetworkSecurityAgent.ps1` - yangi,
  qo'lda ishlatiluvchi to'g'ridan-to'g'ri o'rnatuvchi.
- `docs_WINDOWS_AGENT_SETUP.md` 5-bo'limi to'liq yangilandi - endi
  Python fayllarini emas, `.exe`ni SYSVOL'ga joylashtirish oqimi.

**HAQIQIY natija (push qilib, kuzatilgan)**: `Build Windows Agent`
workflow'i muvaffaqiyatli o'tdi - `.exe` fayli haqiqatan yaratildi
(hajmi tekshirilgan), va **haqiqiy Windows muhitida** `--help` bilan
ishga tushirilgani tasdiqlandi.

**Topilgan va tuzatilgan 2 ta real xato** (avvalgi `Deploy-
NetworkSecurityAgent.ps1`da, .exe paketini qurish jarayonida
aniqlangan):
1. API kalit/URL **registry**ga yozilardi, lekin Python kodi
   (`os.getenv()`) ularni **muhit o'zgaruvchisi** sifatida o'qiydi -
   bular hech qachon bog'lanmagan bo'lardi. Machine-scope muhit
   o'zgaruvchisiga o'zgartirildi.
2. Xizmat `sc.exe create` orqali o'rnatilardi - lekin pywin32
   xizmatlari o'zining `install` buyrug'i orqali qo'shimcha registry
   ma'lumotini (Python sinf yo'li) yozishi SHART, aks holda SCM
   xizmatni ishga tushira olmaydi. exe'ning o'z install/stop/remove
   buyruqlariga o'zgartirildi.

## Ikkinchi tuzatish: SSH Deploy ruxsatlari (foydalanuvchi savoli)

Foydalanuvchi "SSH orqali kirish uchun qanday ruxsatlar kerak"
so'radi - bu `deploy/network-security-deploy.service`da `root`
o'rniga maxsus, cheklangan `netsecdeploy` foydalanuvchisiga
(`docker` guruhi a'zosi) o'tkazildi, va `docs_DEPLOYMENT_SSH_
AUTOUPDATE.md`ga "0-bosqich: qanday ruxsatlar kerak" bo'limi
qo'shildi (chiquvchi-vs-kiruvchi tushuntirish, SSH kalit fayl
ruxsatlari, `docker` guruhi haqida ochiq ogohlantirish).

## Auto-Deploy (SSH+GitHub, foydalanuvchining production serveri so'rovi bo'yicha)

Foydalanuvchi haqiqiy production mashinasidan (`network1411tas@...`,
`172.16.1.206/22`, Docker bilan) GitHub'dan SSH orqali klonlash va
yangilanganda avtomatik ishga tushirishni so'radi.

Qurilgan: `deploy/auto_deploy.sh` (git fetch/compare/pull/backup/
docker-rebuild/health-check/flock zanjiri) + `deploy/network-security-
deploy.service`+`.timer` (systemd, har 5 daqiqada tekshiradi) +
`docs_DEPLOYMENT_SSH_AUTOUPDATE.md` (SSH deploy key sozlash to'liq
yo'riqnomasi).

**Real test qilingan**: ikkita haqiqiy git repo (GitHub va production
server o'rnini bosuvchi) bilan 4 stsenariy - o'zgarish yo'q holat,
yangi commit bilan to'liq pull+backup+docker+health-check zanjiri
(muvaffaqiyatli va muvaffaqiyatsiz health-check ikkalasi), va bir
vaqtda ikkita jarayonning oldini olish (`flock`). `systemd` unit
fayllari haqiqiy `systemd-analyze verify` orqali tasdiqlangan.

**Topilgan va tuzatilgan test xatosi**: test skriptim backup/docker
compose chiqishini noto'g'ri joydan (`subprocess.run`ning `stdout`
maydonidan) tekshirgan edim - lekin `auto_deploy.sh` bu buyruqlar
chiqishini faqat log faylga yo'naltiradi (`>> "$LOG_FILE"`), skriptning
o'z stdout'iga emas (faqat `log()` funksiyasi orqali yozilgan xabarlar
`tee` bilan ikkalasiga ham boradi). Log fayldan tekshirishga tuzatildi.

## Network Discovery kengaytmasi (10/10 talabiga javoban)

Foydalanuvchi so'ragan 8 qo'shimcha yo'nalishning barchasi qo'shildi:
IPv6 Discovery, VMware/Hyper-V, Kubernetes node discovery, Cloud
(AWS/Azure/GCP), Cisco WLC/Aruba/Ruijie, OT/IoT (qisman - tcp_scanner
orqali), Rejalashtirilgan+Differensial scan, Asset History.

**MUHIM**: sessiya boshida sandbox'da bu modullarning barchasi
allaqachon "ghost fayl" sifatida (avvalgi tugallanmagan urinishdan)
mavjud edi - `CLAUDE.md`dagi ogohlantirishga muvofiq ular qayta
yozilmasdan, sinchiklab ko'rib chiqilib, sifat tasdiqlanib, keyin
**real test qilindi**.

**Real test qilingan (yangi)**:
- Kubernetes Node Discovery - real k3s klasterida (OS image, kubelet versiyasi)
- Scheduled + Differential Scan - real tarmoqda, 4 xil stsenariy (discovered/disappeared/reappeared/dedup)
- IPv6, VMware, Cloud, WLC - graceful-fail (real infratuzilma yo'q, lekin xato ko'tarmasligi tasdiqlangan)

**Topilgan va tuzatilgan 3 ta real xato**:
1. `scheduler.py`da `ip_address` global unique bo'lgani uchun boshqa
   manba orqali mavjud IP bilan differensial scan INSERT to'qnashuvi.
2. `run_full_test.py`dagi differensial scan testida "istalgan ma'lum
   qurilma"ni (`.first()`) "qayta paydo bo'lgan" stsenariysi uchun
   tanlash - bu **faqat PostgreSQL'da** ochilib qoldi (qatorlar
   tartibi SQLite'dan farq qilgani uchun boshqa testdan qolgan,
   joriy tarmoqda mavjud bo'lmagan qurilma tanlanib qolgan edi).
   Tuzatildi: faqat HOZIRGI skanerlashda haqiqatan topilgan IP
   ishlatiladi.
3. Kubernetes testi to'liq test to'plami ichida **flaky** edi (node
   holati vaqtincha "Ready"dan "NotReady"ga qaytib ketishi) - 3 marta
   ketma-ket barqaror "Ready" talab qiluvchi tekshiruv bilan
   tuzatildi, 3 marta ketma-ket ishga tushirib (SQLite) va 2 marta
   (PostgreSQL) barqarorlik tasdiqlandi.

## Network Discovery'da topilgan muhim kashfiyot

Avvalgi bosqichlarda "sandbox'da paket capture umuman ishlamaydi" deb
xulosa qilingan edi (`tcpdump` `lo` interfeysida 0 paket ushlagani
sabab). Bu bosqichda **bu xulosa noto'g'ri ekanligi aniqlandi** -
faqat `lo` (loopback) capture cheklangan, lekin **`eth0` (haqiqiy
tarmoq interfeysi)da to'liq L2/L3 paket capture ishlaydi**. Bu
LLDP/CDP kabi L2 protokollarni **haqiqiy paket jo'natib, haqiqiy
ushlab, haqiqiy parslab** test qilish imkonini berdi (Zeek kabi
"faqat kod, sinab bo'lmaydi" holatidan farqli). **Xulosa**: bir marta
"ishlamaydi" deb topilgan narsani boshqa interfeys/sharoitda qayta
tekshirish foydali bo'lishi mumkin.

## Network Discovery'da topilgan va tuzatilgan real xatolar (4 ta)

1. ARP scan'da "DUP" (takroriy) javoblar alohida yozuv sifatida
   qo'shilib qolgani - deduplikatsiya bilan tuzatildi.
2. CDP test paketi noto'g'ri Ethernet freyming bilan qurilgan edi
   (oddiy `Ether()` - CDP esa haqiqiy 802.3 LLC/SNAP inkapsulyatsiyasini
   talab qiladi) - `Dot3()/LLC()/SNAP()` bilan tuzatildi.
3. Debug skriptida `scapy.contrib.cdp` import qilinmagani sababli
   SNAP->CDP avtomatik bog'lanish (`bind_layers`) faollashmagan edi.
4. `asset_inventory.py`da `discovery_source` maydoni har doim ustidan
   yozilardi - ARP orqali (MAC bilan) topilgan boy ma'lumot keyinroq
   ICMP orqali (faqat "tirik") qayta ko'rilganda "pasayib" qolardi -
   manba ustuvorligi mantig'i bilan tuzatildi.

## Yakuniy holat - loyiha to'liq

Yangi TZ'dagi 24 bo'limning **deyarli barchasi** (Zeek va Grafana'ning
faqat binary ijrosidan tashqari - ikkalasi ham tarmoq cheklovi sabab,
lekin kod/konfiguratsiya darajasida to'liq va test qilingan) qurilgan
va real test qilingan. Rasmiy hujjatlar, Encryption at Rest, API Token
boshqaruvi - barchasi qo'shildi.

## Encryption at Rest'da topilgan va tuzatilgan real xato

`db/models.py`da `mfa_secret = Column(String(64))` edi - ochiq Base32
TOTP kaliti 32 belgi bo'lgani uchun bu yetarli edi. Lekin Fernet bilan
shifrlangandan keyin qiymat **~140 belgi**ga cho'zilib ketadi. SQLite
VARCHAR uzunlik cheklovini UMUMAN MAJBURLAMAYDI (shuning uchun lokal
testlarda bu xato yashiringan edi), lekin **PostgreSQL buni qat'iy
talab qiladi** va xatoni chiqarib berdi. Tuzatildi: `String(255)`ga
kengaytirildi. **Xulosa (yana bir marta tasdiqlandi)**: bazaga bog'liq
xatolarni faqat SQLite'da emas, albatta PostgreSQL'da ham sinash kerak
- bu loyihada shu sababli hozirgacha kamida 3-4 marta real xato
topilgan (bu xil "SQLite kechiradi, PostgreSQL kechirmaydi" muammolar
darajasi).

## Backup/Restore'da topilgan va tuzatilgan real xato

Birinchi PostgreSQL testida `pg_dump` (flag'siz) standart holatda `CREATE
TABLE` buyruqlarini ham dump qiladi. Bazada jadvallar allaqachon mavjud
bo'lgani (ilova ishga tushganda SQLAlchemy avtomatik yaratgan) uchun
restore paytida "relation already exists" xatolari kelib chiqadi, va bu
PostgreSQL'da **butun tranzaksiyani bekor qiladi** - shu sabab undan
keyingi haqiqiy ma'lumot (`COPY`) buyruqlari **jim ravishda e'tiborsiz
qoldirilib**, ma'lumot yo'qoladi (hech qanday xato ko'rsatilmasdan!).
Bu ayniqsa xavfli, chunki `restore_backup()` "muvaffaqiyatli" deb
qaytargan edi (psql default holatda xatolardan keyin ham davom etadi,
returncode=0). Tuzatildi: `pg_dump`ga `--clean --if-exists` (avval
mavjud obyektlarni tozalaydi) va `psql` restore'ga `-v ON_ERROR_STOP=1`
(birinchi xatoda to'xtaydi, jim yo'qotmaydi) qo'shildi.

## Yangi TZ bo'yicha yakuniy holat

**Barcha 24 bo'limdan qurilishi mumkin bo'lganlari (kod + real test bilan)
qurildi.** Qolgan bo'limlar (SIEM'ning to'liq Windows Event/Sysmon/
Auditd integratsiyasi, to'liq Grafana/Live Map dashboardlari, RBAC'dan
tashqari to'liq Audit Log/Encryption/API Token boshqaruvi, Backup/
Restore/Snapshot, rasmiy hujjatlar - Admin/User/API/Installation/DR
Guide'lar) - bular tabiatan **"kengaytirish" emas, balki mavjud
narsalarni chuqurlashtirish/hujjatlashtirish** ishlari, alohida so'rov
bo'yicha davom ettiriladi.

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
