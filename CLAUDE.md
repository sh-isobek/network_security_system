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

**Joriy: 66/66 test o'tadi (`run_full_test.py`).**

## Foydalanuvchi qulayligi: API_SERVER_URL doimiy SYSVOL faylidan

Foydalanuvchi so'radi: har safar yangi `Deploy-NetworkSecurityAgent.ps1`
versiyasini GitHub'dan yuklab olganda, `API_SERVER_URL`ni qo'lda
qayta sozlash shart bo'lmasin.

**Tasdiqlangan holat**: `AGENT_API_KEY` allaqachon to'g'ri
arxitekturaga ega edi (alohida `api_key.secret` SYSVOL faylidan
o'qiladi, skriptga hech qachon qattiq yozilmagan). `API_SERVER_URL`
esa hali skriptning **parametr standart qiymati** (umumiy shablon,
`http://172.16.0.5:8443`) sifatida qolgan edi - foydalanuvchi har
safar yangi skript versiyasini olganda buni qo'lda o'z haqiqiy server
manziliga (`172.16.1.206`) o'zgartirishi kerak edi.

**Tuzatish**: `API_SERVER_URL` endi **`AGENT_API_KEY` bilan bir xil
naqsh** orqali ishlaydi - agar SYSVOL'da alohida `api_server_url.txt`
fayli mavjud bo'lsa, o'sha qiymat skript parametridan **ustun**
qo'yiladi. Bu faylni foydalanuvchi **FAQAT BIR MARTA** yaratadi -
undan keyin `.exe`/`Deploy-NetworkSecurityAgent.ps1` qancha marta
yangilansa ham, bu faylga hech qachon tegilmaydi.

**Real test qilingan**: Python orqali PowerShell mantig'i
simulyatsiya qilinib, (1) fayl mavjud bo'lganda skript standart
qiymatini to'g'ri almashtirishi, (2) fayl mavjud bo'lmaganda xatosiz
standart qiymatga qaytishi tasdiqlandi.

`docs_WINDOWS_AGENT_SETUP.md` yangilandi - yangi `api_server_url.txt`
fayli diagramma va sozlash qadamlariga qo'shildi, "versiya
yangilanganda bu ikkala faylga tegishning hojati yo'q" aniq
ta'kidlandi.

VERSION 1.0.7 -> 1.0.8.

## Dashboard: qurilma "tarmoqqa ulangan/uzilgan" holati + qurilmalar soni (production diagrammasi bo'yicha moslashtirish)

Foydalanuvchi production arxitekturasini (Ubuntu Server 172.16.1.206,
server `.env`da faqat `AGENT_API_KEY`, Windows Agent'da SYSVOL orqali
`API_SERVER_URL`+`AGENT_API_KEY`) diagramma bilan tasdiqlab, Dashboard'ni
shunga moslab: (1) qurilmalarning tarmoqqa ulangan/ulanmaganini,
(2) qurilmalar sonini, (3) fayl tekshirish oqimini "ishlaydigan holatga"
keltirishni so'radi.

**Tekshiruv natijasi**: server<->agent konfiguratsiya arxitekturasi
(`agent_api` xizmati `env_file: .env` orqali FAQAT `AGENT_API_KEY`ni
o'qiydi, `api_server_url.txt`/`AGENT_API_KEY` SYSVOL naqshi allaqachon
1.0.8'da qurilgan) va fayl tekshirish zanjiri (`file_analysis_engine`,
`suricata_reader`, `deep_scan_engine` - barchasi `docker-compose.yml`da
PROFILSIZ, standart holatda ishga tushadi) **allaqachon so'ralgan
diagrammaga mos edi** - o'zgartirish talab qilinmadi.

**Haqiqiy bo'shliq**: Dashboard'da qurilmaning tarmoqqa ulangan/uzilgan
holati (onlayn/offlayn) umuman ko'rsatilmasdi, va `/devices` sahifasi
sarlavhasi jami qurilmalar sonini emas, faqat qaytarilgan (200 taga
cheklangan) ro'yxat uzunligini ko'rsatardi.

**Qurilgan**:
- `config/settings.py`: yangi `DEVICE_OFFLINE_THRESHOLD_MINUTES`
  (standart 60 daqiqa, `network_discovery.scheduler`ning standart
  1 soatlik skanerlash intervaliga mos) - `Device.last_seen` shu
  vaqtdan eski bo'lsa, qurilma "OFFLAYN" hisoblanadi.
- `dashboard/app.py`: `/devices` va `/` (index) - onlayn/offlayn
  hisob-kitob, `/devices?status=online|offline` filtri, va `/devices`
  sarlavhasi endi haqiqiy JAMI sonni ko'rsatadi (ro'yxat cheklovidan
  mustaqil).
- `dashboard/templates/devices.html`, `index.html`: ONLAYN/OFFLAYN
  badge, jami/onlayn/offlayn statistika kartochkalari.

**Real test qilingan**: yangi `run_full_test.py` test #66 - real HTTP
orqali (`dash_app.test_client()`) ikkita test qurilma (so'nggi 2
daqiqada ko'rilgan va 5 soat oldin ko'rilgan) yaratilib, `/devices`
sahifasida to'g'ri ONLAYN/OFFLAYN belgilanishi, status filtri, va
sarlavhadagi haqiqiy jami son tasdiqlandi. Ham SQLite, ham PostgreSQL'da
o'tdi.

**Diqqat (halol)**: bu "onlayn/offlayn" belgisi `Device.last_seen`
(DHCP/DNS/Suricata trafigi, ARP/ICMP skanerlash yoki UniFi sinxronizatsiyasi
orqali yangilanadi) asosida - alohida `network_discovery.scheduler --loop`
xizmati (host tarmoq huquqi talab qiladigan, `--profile discovery`
ortidagi) ishlamasa ham universal ishlaydi, lekin bu "ping orqali real
vaqtli" tekshiruv emas - eng so'nggi ko'rilgan trafik/skanerlash vaqtiga
asoslangan taxmin.

## O'ZIM QO'SHGAN REGRESSIYA: GitHub CI'ning haqiqiy Start-Service tekshiruvi tomonidan ushlandi

Oldingi commit'da (`_windows_watch_dirs()` diagnostika loglari)
`logger.info()/.warning()/.debug()` chaqiruvlarini qo'shgandim, lekin
**`logger` `service_wrapper.py`da import qilinmagan edi** (fayl
faqat `from windows_agent.agent import EndpointAgent` qilar edi,
`logger`ni EMAS). Bu sintaksis darajasida (`ast.parse()`) hech qanday
xato bermaydi - faqat funksiya HAQIQATAN chaqirilganda `NameError`
beradi.

**Bu xato mening o'z sinovlarimni aylanib o'tdi** (faqat `ast.parse()`
orqali sintaksis tekshiruvi, funksiyani haqiqatan chaqirmasdan), lekin
**GitHub CI'ning yangi, qat'iy `Start-Service` tekshiruvi** (avvalgi
sessiyada qo'shilgan) buni **darhol** ushladi - xizmat haqiqiy Windows
runner'ida ishga tushmadi.

**Tuzatish**: `from agent_core.agent import logger` qo'shildi.

**Real test qilingan (bu safar HAQIQATAN)**: `pywin32` modullari
(`win32event`, `win32service`, `win32serviceutil`, `servicemanager`)
**soxta (mock) qilinib**, `service_wrapper.py` **to'liq import
qilindi va `_windows_watch_dirs()` HAQIQATAN chaqirildi** - bu safar
faqat sintaksis emas, balki **haqiqiy bajarilish** tasdiqlandi.

VERSION 1.0.6 -> 1.0.7.

**MUHIM SABOQ**: bu holat GitHub Actions CI'ga qo'shilgan **haqiqiy
`Start-Service` tekshiruvi**ning qanchalik qimmatli ekanligini
isbotladi - agar bu tekshiruv bo'lmaganida, bu regressiya
foydalanuvchi tomonidan **production'da** aniqlangan bo'lardi. Bu
shuningdek shuni ko'rsatadiki, `ast.parse()` orqali sintaksis
tekshiruvi **YETARLI EMAS** - Python'da `NameError` kabi xatolar
faqat kod HAQIQATAN bajarilganda ma'lum bo'ladi, shuning uchun
bundan buyon Windows-maxsus kod uchun ham (imkon qadar) mock-asosli
haqiqiy bajarilish testlari yozish zarur.

## O'N BESHINCHI marta topilgan xato: _windows_watch_dirs() Downloads papkasini jim ravishda o'tkazib yuborgan

Proksi tuzatishi (1.0.5) deploy qilingandan keyin, xizmat `1.0.4 ->
1.0.5` to'g'ri yangilangan bo'lsa-yu, agent qayta yoqilgandan so'ng
**faqat** `C:\WINDOWS\TEMP` va `C:\WINDOWS\Temp`ni kuzatgan -
foydalanuvchining `Downloads` papkasi butunlay ro'yxatdan tashqarida
qolgan, hech qanday xato yoki ogohlantirish log qilinmagan edi.

**ILDIZ SABAB (ehtimoliy)**: bu - loyihada bir necha marta uchragan
xato turkumi bilan bir xil: `os.environ.get("SystemDrive", "C:")`
faqat `SystemDrive` **umuman mavjud bo'lmasa** standart qiymatni
qo'llaydi - agar u **bo'sh qator** sifatida mavjud bo'lsa (LocalSystem
kontekstida bu ehtimol), standart qiymat qo'llanilmay,
`os.path.join("", "Users")` **nisbiy** `"Users"` yo'liga aylanadi -
bu esa xizmat ish katalogiga (odatda `C:\Windows\System32`) nisbatan
qidiriladi va **hech qachon topilmaydi**, hech qanday xato ham
bermaydi (`os.path.isdir()` xatoni yutib, jim `False` qaytaradi).

**Tuzatish**:
1. `_windows_watch_dirs()`ga **to'liq diagnostika loglari** qo'shildi
   - endi har bir profil (`topildi`/`topilmadi`/`kirish yo'q`) va
   yakuniy kuzatiladigan papkalar ro'yxati aniq log qilinadi - bu
   kelajakda shunga o'xshash muammolarni bir zumda aniqlash imkonini
   beradi.
2. `SystemDrive`ga tayanish o'rniga, avval **standart, deyarli
   universal `C:\Users`** yo'li sinaladi (fallback zanjiri) - bu
   `SystemDrive` noto'g'ri/bo'sh bo'lgan taqdirda ham ishlaydi.

**Real test qilingan**: Linux'da `C:\Users`ga o'xshash haqiqiy papka
strukturasi yaratilib, `SystemDrive`ning **ataylab noto'g'ri**
qiymati bilan - fallback mexanizmi to'g'ri ishlab, foydalanuvchi
profilini (Downloads/Desktop) topganini, tizim profillarini
(`Public`/`Default`) to'g'ri o'tkazib yuborganini tasdiqladi.

VERSION 1.0.5 -> 1.0.6.

**O'N BESHINCHI MARTA TASDIQLANGAN SABOQ**: bu - avvalgi (proksi)
tuzatishdan **mustaqil, alohida** xato edi - ikkalasi bir vaqtda,
bitta amaliy sinovda ochilib qoldi. Bu shuni ko'rsatadiki, murakkab
tizimlarda bir nechta mustaqil muammo **bir vaqtda** mavjud
bo'lishi mumkin, va har birini alohida, aniq diagnostika orqali
tasdiqlash zarur - "bitta tuzatish barcha muammoni hal qildi" degan
xulosaga shoshilinch kelmaslik kerak.

## O'N TO'RTINCHI marta topilgan xato: LocalSystem tizim proksi sozlamalari

Xizmat `Running` holatida, `--startup auto` ishlagan, VERSION solishtiruvi
to'g'ri ishlagan bo'lsa-yu - foydalanuvchi "Isobek"da agent hech qanday
faylni serverga yubora olmasligini xabar qildi. Agent logida **har
bir** so'rov `ConnectionResetError (10054)` bilan muvaffaqiyatsiz
bo'lgan.

**Hal qiluvchi dalil**: xuddi shu tarmoq, xuddi shu API kaliti bilan
foydalanuvchining **shaxsiy hisobi** orqali (`Invoke-WebRequest`)
serverga **muvaffaqiyatli** ulandi - faqat xizmat (**LocalSystem**)
har doim muvaffaqiyatsiz bo'lardi.

**ILDIZ SABAB**: Python `requests` kutubxonasi standart holatda
**muhit/tizim darajasidagi proksi sozlamalarini** (masalan Group
Policy orqali o'rnatilgan yoki noto'g'ri sozlangan WinHTTP proksi)
hurmat qiladi. LocalSystem hisobi bunday tizim darajasidagi
sozlamalarni meros qilib oladi, interaktiv foydalanuvchi sessiyasi
esa (turli sabablarga ko'ra - foydalanuvchi darajasidagi sozlama,
yoki umuman proksisiz) muvaffaqiyatli ulanardi.

**Qo'shimcha kuzatuv**: `send_heartbeat()` xuddi shu zaif naqshga
ega edi, lekin uning xatosi faqat `debug` darajasida yozilardi
(standart `INFO` darajasida ko'rinmasdi) - bu "agent ulandi" degan
noto'g'ri taassurot qoldirgan bo'lishi mumkin, aslida heartbeat ham
hech qachon muvaffaqiyatli bo'lmagan bo'lishi mumkin edi.

**Tuzatish**: `agent_core/agent.py`dagi barcha 3 ta `requests.post()`
chaqiruviga (`check_hash`, `report_incident`, `send_heartbeat`) aniq
`proxies={"http": None, "https": None}` qo'shildi - bizning ichki
server bilan aloqa hech qachon tashqi proksiga muhtoj emas, shuning
uchun uni butunlay o'chirib qo'yish xavfsiz va to'g'ri.

**Real test qilingan**: real API server ishga tushirilib, **ataylab
noto'g'ri, mavjud bo'lmagan proksi** (`HTTP_PROXY`/`HTTPS_PROXY`
muhit o'zgaruvchilari) o'rnatilgan holda - tuzatishsiz `requests.post()`
chaqiruvi **`ProxyError`** bilan muvaffaqiyatsiz bo'lishi, tuzatilgan
(`proxies=None`) chaqiruv esa **muvaffaqiyatli** o'tishi taqqoslab
tasdiqlandi. Bu aynan "Isobek"dagi xatoni takrorlaydi va tuzatishni
tasdiqlaydi.

VERSION 1.0.4 -> 1.0.5.

**O'N TO'RTINCHI MARTA TASDIQLANGAN SABOQ**: bu xato **faqat**
foydalanuvchining "shaxsiy hisobim bilan sinab ko'raymi" degan oddiy
taklifi orqali ochilib qoldi - ikkala kontekst (LocalSystem va
interaktiv foydalanuvchi) orasidagi solishtiruv, aynan Windows
xizmatlarini ishlab chiqishning yana bir klassik, chuqur yashiringan
tuzog'ini fosh qildi.

## CI'da topilgan qo'shimcha real xato: karantin papkasi root-huquqsiz ishlamasdi

Web Activity/Karantin integratsiyasi push qilingandan keyin, GitHub
Actions CI **muvaffaqiyatsiz** bo'ldi (lokal sandbox'da esa root
sifatida ishlagani sabab bu ko'rinmagan edi):

```
PermissionError: [Errno 13] Permission denied: '/var/lib/network-security'
```

**ILDIZ SABAB**: GitHub Actions runner **root bo'lmagan foydalanuvchi**
sifatida ishlaydi (mening sandbox'imdan farqli - men root edim).
`engine/quarantine.py`/`agent_core/quarantine.py`dagi standart
karantin papkalari (`/var/lib/network-security/...`) bunday
foydalanuvchi uchun yaratib bo'lmaydigan joyda, va `os.makedirs()`
hech qanday `try/except` bilan o'ralmagan edi - bu **butun test
to'plamini** (hatto mening yangi karantin testlarimga aloqasi
bo'lmagan, oldindan mavjud "Fayl analiz pipeline" kabi testlarni ham)
qulatib qo'ygan edi.

**Ikkinchi xato**: `agent_core/quarantine.py`ning Linux yo'li
(`/var/lib/network-security-agent/quarantine`) hech qanday muhit
o'zgaruvchisi orqali qayta belgilanmasdi - mening test kodim esa
noto'g'ri (`ProgramData`, faqat Windows uchun) o'zgaruvchini
ishlatgani sabab, aslida hech qachon haqiqiy yo'lni sinamagan edi.

**Tuzatish**:
1. Ikkala `quarantine.py` faylida ham papka yo'li **HAR CHAQIRUVDA
   dinamik** o'qiladigan qilindi (modul darajasidagi "muzlab qolgan"
   konstanta emas - bu loyihada bir necha marta uchragan xato
   turkumi).
2. `os.makedirs()` `try/except OSError` bilan o'raldi - ruxsat
   yo'qligida butun pipeline qulamaydi, aniq "karantinga olish
   muvaffaqiyatsiz" xabari bilan davom etadi.
3. `agent_core/quarantine.py`ga yangi `AGENT_QUARANTINE_DIR` muhit
   o'zgaruvchisi qo'shildi (Linux/Mac uchun ham qayta belgilash
   imkoni), va mening test kodim to'g'ri o'zgaruvchiga tuzatildi.

**Real test qilingan (root VA root bo'lmagan foydalanuvchi bilan)**:
bu sandbox'da maxsus `ciuser` (root bo'lmagan) yaratib, `quarantine_
file()` va `deep_scan_engine`ning to'liq zanjiri shu foydalanuvchi
nomidan ishga tushirilib, ikkalasi ham **qulamasdan, graceful xato
bilan** davom etishi tasdiqlandi - bu aynan GitHub Actions CI
muhitini haqiqiy takrorlaydi.

## Web Activity (saytlar tarixi) + Xavfsiz Karantin integratsiyasi (ikkinchi tashqi manba zip)

Foydalanuvchi yana bir marta tashqi manbadan (`network_security_system-
web-activity-added.zip`) qo'shimcha tuzatishlar yubordi. Diqqat bilan
`diff -rq` orqali to'liq tekshirilgach, bu zip **ikkita mustaqil,
sifatli funksiya** olib kelganini aniqladim:

### 1) Web Activity - qurilma qaysi saytga qachon kirgani

- `db/models.py`: yangi `WebAccessLog` jadvali (`source_ip`, `domain`,
  `url`, `protocol`, `status_code` va h.k.)
- `collectors/zeek_reader.py`: yangi `process_http`/`process_ssl`
  funksiyalari - Zeek `http.log`/`ssl.log`'dan to'liq URL (HTTP) yoki
  TLS SNI orqali domen (HTTPS, shifrlanganligi sabab faqat domen)
  saqlaydi.
- `engine/parser_engine.py`: DNS so'rovlari ham `WebAccessLog`ga
  yoziladi (Zeek yo'q tarmoqlarda ham asosiy qidiruv imkoni uchun).
- `dashboard/`: yangi `/web-activity` sahifasi - sayt/IP/hostname/
  protokol/sana bo'yicha filtrlash.
- **Halol hujjatlashtirilgan cheklov** (`docs_WEB_ACTIVITY_INTEGRATION.md`):
  "DNS so'rovi sahifa ko'rilganini KAFOLATLAMAYDI - faqat domen
  so'ralganini bildiradi."

### 2) Xavfsiz Karantin - eski `TODO` o'rniga haqiqiy ishlaydigan kod

- `agent_core/quarantine.py` / `engine/quarantine.py`: fayl avval
  karantin papkasiga NUSXALANADI, nusxa SHA256 orqali TASDIQLANADI,
  faqat SHUNDAN KEYIN asl fayl o'chiriladi. Agar nusxa SHA256 mos
  kelmasa, asl fayl SAQLANIB QOLADI (real test bilan tasdiqlangan
  xavfsizlik nazorati).
- `api/server.py` va `engine/file_analysis_engine.py`: VirusTotal
  uchun `confirmed` chegara mantig'i - bitta dvigatel signali endi
  avtomatik karantinga OLIB KELMAYDI (soxta-pozitiv xavfi). Kamida 3
  dvigatel VA hisobot beruvchilarning kamida 5% signal berishi talab
  qilinadi. Mahalliy blacklist va MalwareBazaar har doim "tasdiqlangan".
- `engine/deep_scan_engine.py`: YARA/ClamAV signal bersa, fayl
  HAQIQATAN xavfsiz karantinga olinadi (avvalgi "TODO: karantin/
  bloklash backend hali ulanmagan" placeholder o'rniga).

### ⚠️ Muhim ehtiyot chorasi

Bu zip mening **eng so'nggi Windows Agent tuzatishlarimdan** (SCM
Control Dispatcher, `--startup auto`, ko'p-foydalanuvchi kuzatish)
**orqada** edi - shuning uchun `agent_core/agent.py`, `windows_agent/
service_wrapper.py`, `Deploy-NetworkSecurityAgent.ps1` fayllarini
**ustidan yozmadim** - faqat yangi Web Activity/Karantin funksiyasini
qo'lda, ehtiyotkorlik bilan qo'shdim (o'zim yaratgan `EndpointAgent.
start_background()`/`.stop()` arxitekturasi buzilmadi).

### Real test qilingan (barchasi)

- Zeek HTTP/SSL/DNS → `WebAccessLog` → Dashboard: real sintetik Zeek
  yozuvlari va real HTTP orqali (filtrlash ham) tasdiqlandi.
- Karantin: real fayl bilan (SHA256 tasdiqlash, mos kelmasa RAD
  ETISH) ham `agent_core`, ham `engine` versiyasida tekshirildi.
- VirusTotal `confirmed` chegarasi: 3 stsenariy (mahalliy/past
  ishonch/yuqori ishonch) real DB bilan tasdiqlandi.
- Deep Scan: **haqiqiy EICAR test signature** fayli bilan to'liq
  zanjir (aniqlash → karantin → asl fayl o'chirilishi) tasdiqlandi.

### Topilgan va tuzatilgan real xato

Integratsiya jarayonida `/web-activity` route **ikki marta**
aniqlanib qolgani (Flask'ning "View function mapping is overwriting
an existing endpoint" xatosi) aniqlandi - bu barcha 11 mavjud testni
vaqtincha buzgan edi. Ortiqcha nusxa o'chirilib tuzatildi.

## O'N UCHINCHI marta topilgan xato: SCM Control Dispatcher aniq chaqirilmagan (PyInstaller+pywin32 muammosi)

`ReportServiceStatus(SERVICE_RUNNING)` va `--startup auto`
tuzatilgandan (tashqi manba integratsiyasi) KEYIN ham, foydalanuvchi
xizmatni yangi `1.0.3` bilan sinaganida, deploy.log **aynan bir xil**
umumiy xatoni ko'rsatdi: `"Cannot start service NetworkSecurityEndpointAgent
on computer '.'"`.

**Muhim kuzatuv**: `install`/`remove`/`debug` (argumentlar bilan
chaqirilganda) har doim mukammal ishlagan - bu `win32serviceutil.
HandleCommandLine()`ning argumentlarni to'g'ri qayta ishlashini
tasdiqlaydi. Lekin Windows SCM xizmatni HAQIQATAN ishga tushirganda,
uni **hech qanday argumentsiz** chaqiradi - bu holatda dastur o'zi
"men Service Control Dispatcher orqali chaqirilyapman" deb tushunishi
kerak. Bu - PyInstaller bilan "muzlatilgan" (frozen) yagona-fayl
`pywin32` xizmatlarining **tanilgan muammosi**: `HandleCommandLine()`
buni avtomatik aniqlashi kerak edi, lekin frozen exe'larda bu
aniqlash ishonchsiz bo'lishi mumkin.

**Tuzatish**: `sys.argv` uzunligini ANIQ tekshirib, argument
bo'lmasa (`len(sys.argv) == 1`) `servicemanager.Initialize()` /
`PrepareToHostSingle()` / `StartServiceCtrlDispatcher()`ni QO'LDA
chaqirish - `HandleCommandLine()`ning ichki avtomatik aniqlashiga
tayanmasdan.

**CI'ga ham muhim kuchaytirish**: avvalgi CI tekshiruvim faqat
xizmatning **ro'yxatdan o'tishini** (`sc.exe query`) tekshirardi -
bu xizmat **haqiqatan ishga tushishi**ni kafolatlamaydi (aynan shu
farq real production xatosining o'zi edi!). Endi CI'ga **haqiqiy
`Start-Service`** chaqiruvi va holatning `"Running"`ga o'tishini
tasdiqlovchi qadam qo'shildi - bu, agar bu tuzatish ham yetarli
bo'lmasa, keyingi push'da avtomatik ushlanadi.

VERSION 1.0.3 -> 1.0.4.

**O'N UCHINCHI MARTA TASDIQLANGAN SABOQ**: bu holatda avvalgi
"to'g'ri" tuzatish (`ReportServiceStatus`) HAQIQATAN to'g'ri edi,
lekin **yetarli emas edi** - muammoning ikkinchi, chuqurroq qatlami
bor edi (SCM dispatcher chaqiruv mexanizmi). Bu shuni ko'rsatadiki,
"bitta ishonchli tuzatish topilgach ham" - real production sinovi
orqali tasdiqlanmaguncha, muammo to'liq hal bo'lgan deb hisoblash
xato bo'lishi mumkin.

## Tashqi manbadan qo'shimcha tuzatishlar integratsiyasi (foydalanuvchi yuborgan zip)

Foydalanuvchi mustaqil ishlab chiqilgan (boshqa vosita/hamkasb orqali)
tuzatishlar to'plamini zip fayl sifatida yubordi. Diqqat bilan tekshirib
chiqilgach (barcha farqlar `diff` orqali), bu zip:

1. Mening barcha oldingi tuzatishlarimni (USERDNSDOMAIN, idempotentlik,
   exit code, ReportServiceStatus) **to'g'ri** o'z ichiga olgan edi.
2. **3 ta qo'shimcha, haqiqiy real production xatosini** ham topib
   tuzatgan edi:

   a) **`--startup auto`** yetishmasligi - Deploy skripti xizmatni
      standart (odatda "Manual") ishga tushirish turi bilan o'rnatar
      edi. Bu, foydalanuvchining haqiqiy `Get-WinEvent` natijasida
      "Тип запуска службы: Вручную" orqali tasdiqlangan - xizmat hatto
      ishga tushirilgandan keyin ham, KEYINGI qayta yoqilishlarda SCM
      tomonidan avtomatik ishga tushirilmasdi.

   b) **Ko'p-foydalanuvchi kuzatish** - `service_wrapper.py` avvalgi
      `_default_watch_dirs()` (`%USERPROFILE%` asosida) ishlatar edi -
      bu LocalSystem hisobi ostida mazmunsiz edi (bu allaqachon
      "hal qilinmagan masala" sifatida hujjatlashtirilgan edi). Yangi
      `_windows_watch_dirs()` funksiyasi `C:\Users\*` ostidagi BARCHA
      haqiqiy foydalanuvchi profillarini avtomatik aniqlaydi.

   c) **`LOCAL_CACHE_FILE`** (hash keshi) ham `agent.log` bilan bir
      xil nisbiy-yo'l muammosiga ega edi - endi mutlaq, xavfsiz yo'lga
      bog'liq.

   d) **CI workflow'ga** haqiqiy Windows runner'ida SCM ro'yxatdan
      o'tishini tekshiruvchi (`sc.exe query`) yangi qadam qo'shilgan -
      bu bizning butun "xizmat 'muvaffaqiyat' deb log qilingan, lekin
      SCM'da yo'q" muammosini HAR PUSH'DA avtomatik ushlaydi.

3. `agent_core/agent.py`ga yangi, tozaroq arxitektura: `EndpointAgent.
   start_background()`/`.stop()` metodlari - heartbeat alohida
   `threading.Thread`da, Windows Service'ning bloklanmasdan ishga
   tushishini ta'minlaydi.

**Integratsiya jarayoni**: barcha 3 fayl (`agent_core/agent.py`,
`windows_agent/service_wrapper.py`, `deploy/windows_agent_gpo/Deploy-
NetworkSecurityAgent.ps1`) va CI workflow'i bizning repo'ga
qo'shildi, YANGI kod uchun 2 ta qo'shimcha regressiya testi yozildi
(`start_background`/`stop`ni real HTTP orqali, va `--startup auto`/
ko'p-foydalanuvchi funksiyasi/CI SCM tekshiruvi borligini tasdiqlovchi
testlar). Mening avvalgi test #54 (ReportServiceStatus) ham
saqlanib qoldi va yangi fayllar bilan muvaffaqiyatli o'tdi.

VERSION 1.0.2 -> 1.0.3.

**MUHIM SABOQ**: bu holat shuni ko'rsatdiki, tashqi manbadan kelgan
tuzatishlarni **ko'r-ko'rona qabul qilish yoki rad etish** o'rniga,
har doim **diqqat bilan diff qilish, to'liq o'qib chiqish, va o'z
test to'plamiga qarshi sinash** kerak - bu holatda tashqi manba
haqiqatan yuqori sifatli, qo'shimcha qiymat keltiruvchi ish bo'lib
chiqdi.

## O'N IKKINCHI marta topilgan xato: HAQIQIY TUB SABAB - ReportServiceStatus(SERVICE_RUNNING) yetishmagan edi

Log fayl yo'li tuzatilgandan keyin ham (VERSION solishtiruvi endi
to'g'ri ishladi - "1.0.0 -> 1.0.1", bu oldingi tuzatish ishlaganini
tasdiqladi), xizmat hali ham **"Cannot start service"** bilan
qulardi. Windows System Event Log'ning o'zidan (Service Control
Manager provayderi) **aniq matn** olindi:

```
The service did not respond to the start or control request in a
timely fashion.
Timeout (30000 ms) waiting for service connection.
```

**HAQIQIY TUB SABAB**: `windows_agent/service_wrapper.py`ning
`SvcDoRun()` metodida `self.ReportServiceStatus(win32service.
SERVICE_RUNNING)` chaqiruvi **umuman yo'q edi**! Bu - Windows Service
Control Manager'ga "men muvaffaqiyatli ishga tushdim, ishlayapman"
deb ANIQ signal beruvchi MAJBURIY chaqiruv - `win32serviceutil.
ServiceFramework` bazaviy sinfi buni **avtomatik qilmaydi**, har bir
xizmat o'zi `SvcDoRun()` ichida chaqirishi SHART. Bu signal
yo'qligi sabab SCM har doim 30 soniyadan keyin xizmatni majburan
o'chirar edi - garchi pastdagi Python kodi (`EndpointAgent`,
`FileMonitor`) o'zi to'g'ri ishlagan bo'lsa ham (bu aynan nima uchun
`debug` rejimida - bu maxsus, SCM'ning 30 soniyalik talabini chetlab
o'tadigan rejim - mukammal ishlaganini tushuntiradi).

**Tuzatish**: `ReportServiceStatus(win32service.SERVICE_RUNNING)`
`SvcDoRun()`ning boshida, `EndpointAgent` yaratilishidan OLDIN
qo'shildi - SCM'ga imkon qadar tezroq signal berish uchun.

`run_full_test.py`ga doimiy regressiya himoyasi qo'shildi (chaqiruv
mavjudligini VA to'g'ri tartibda - agent yaratilishidan oldin -
ekanligini tekshiradi). VERSION 1.0.1 -> 1.0.2.

**O'N IKKINCHI MARTA TASDIQLANGAN SABOQ**: bu - eng uzoq, eng
qiyin diagnostika zanjiri edi (12 marta ketma-ket tuzatish). Haqiqiy
tub sabab faqat **Windows System Event Log'ning o'z, aniq matnli**
xabarini (SCM provayderi orqali) olib, uni pywin32'ning umumiy
xizmat freymvork talablari bilan solishtirib ko'rgandan keyin
topildi - bu shuni ko'rsatadiki, ba'zan eng foydali diagnostika
vositasi ilova logining o'zi emas, balki operatsion tizimning o'z
tizim logidir.

## O'N BIRINCHI marta topilgan xato: TUB SABAB - log fayli nisbiy yo'l, LocalSystem ish katalogi muammosi

Barcha oldingi tuzatishlardan (USERDNSDOMAIN, GPO kesh, Security
Filtering, idempotentlik, exit code) keyin, `debug` rejimi orqali
(pywin32'ning standart diagnostika vositasi) **aniq xato topildi**:
agent debug rejimida (interaktiv foydalanuvchi sifatida) **mukammal**
ishlaydi, lekin haqiqiy Windows Service (LocalSystem hisobi) sifatida
`"Cannot start service"` bilan qulaydi.

**ILDIZ SABAB (nihoyat, tub sabab)**: `agent_core/agent.py`da
`logging.basicConfig()` **MODUL IMPORT vaqtida**, hech qanday
`try/except`siz ishga tushadi, va standart log fayli **nisbiy yo'l**
(`"./agent.log"`) bilan yozilgan edi. Windows Service LocalSystem
hisobi ostida ishga tushirilganda, standart ish katalogi
`C:\Windows\System32\` bo'ladi (`.exe`ning o'z joylashgan katalogi
EMAS) - bu yerga yozish/import muammoli bo'lib, butun modul importi
(demak butun xizmat) DARHOL qulab tushishiga olib keldi.

**Tuzatish**: `_default_log_file()` funksiyasi qo'shildi - Windows'da
`%ProgramData%\NetworkSecurityAgent\agent.log` (mutlaq, ish
katalogiga bog'liq bo'lmagan, LocalSystem ham yoza oladigan) yo'lni
qaytaradi, Linux/Mac'da eski xatti-harakat saqlanib qoladi. Har
qanday kutilmagan xatoda ham (masalan ProgramData'ga yoza olmasa)
import buzilmasligi uchun keng `try/except` bilan o'ralgan.

**Muhim ochilmagan masala (kelajakdagi ish)**: LocalSystem hisobi
ostida `%USERPROFILE%` haqiqiy foydalanuvchi (`i.shunkorov-su`)
profiliga emas, balki LocalSystem'ning o'z (mazmunsiz) profiliga
ishora qiladi - bu `Downloads`/`Desktop` kabi standart kuzatish
papkalari **mavjud bo'lmasligi va jimgina o'tkazib yuborilishi**ga
olib keladi (xizmat endi qulamaydi, lekin haqiqiy foydalanuvchi
papkalarini kuzatmaydi ham). Bu - alohida, keyingi bosqichda hal
qilinishi kerak bo'lgan arxitektura masalasi (masalan barcha
login qilgan foydalanuvchilarning profillarini avtomatik aniqlash).

`run_full_test.py`ga doimiy regressiya himoyasi qo'shildi.

**O'N BIRINCHI MARTA TASDIQLANGAN SABOQ**: bu - eng chuqur, eng
qiyin aniqlanadigan xato edi (10 marta oldingi urinishlardan keyin
topilgan) - `pywin32`ning o'zining **standart diagnostika vositasi**
(`debug` buyrug'i) ishlatilmaguncha yashiringan bo'lib qoldi. Bu
"interaktiv rejimda ishlaydi, xizmat sifatida ishlamaydi" farqi -
Windows xizmatlarini ishlab chiqishda **klassik, tez-tez uchraydigan**
tuzoq (ish katalogi, foydalanuvchi profili konteksti farqlari).

## O'NINCHI marta topilgan xato: tashqi .exe xatosi PowerShell tomonidan sezilmagan

Idempotentlik tuzatilgandan keyin foydalanuvchi qayta sinadi -
`deploy.log`da yana **"Xizmat .exe orqali o'rnatildi"** yozildi, lekin
`Get-Service` xizmat **umuman topilmasligini** ko'rsatdi.

**ILDIZ SABAB**: PowerShell'da `& $exePath install` (tashqi dastur
chaqiruvi) `$ErrorActionPreference = "Stop"`ga **BO'YSUNMAYDI** - bu
faqat PowerShell'ning o'z cmdlet'lariga tegishli. Agar tashqi `.exe`
ichki xatolik bilan muvaffaqiyatsiz bo'lsa (nolinchi bo'lmagan chiqish
kodi bilan chiqsa), PowerShell buni avtomatik "xato" deb bilmaydi -
keyingi qatorga o'tib ketaveradi. Natijada skript **har doim**
"Xizmat .exe orqali o'rnatildi" deb log yozardi, `.exe install`ning
o'zi muvaffaqiyatsiz bo'lgan taqdirda ham.

**Tuzatish**: `$LASTEXITCODE`ni aniq tekshirish qo'shildi (tashqi
dastur chiqish kodi), va - eng muhimi - `install`dan keyin xizmat
**HAQIQATAN SCM'da ro'yxatga olinganini** (`Get-Service` orqali)
alohida tasdiqlash qo'shildi. Shuningdek `Start-Service` atrofiga
`try/catch` qo'shilib, xatolar aniq log qilinadigan bo'ldi.

`run_full_test.py`ga doimiy regressiya himoyasi qo'shildi.

**O'NINCHI MARTA TASDIQLANGAN SABOQ**: bu safar xato PowerShell'ning
o'zining chuqur til semantikasi (tashqi jarayon chaqiruvlari
`$ErrorActionPreference`ga bo'ysunmasligi) bilan bog'liq edi - bu
klassik, ko'p tajribali PowerShell dasturchilar ham duch keladigan
tuzoq, va faqat **haqiqiy, bosqichma-bosqich production sinovi**
orqali ochilib qoldi. Asosiy sabab (pywin32/PyInstaller'ning o'z
`install` buyrug'i nima uchun muvaffaqiyatsiz bo'layotgani) hali
tekshirilmoqda - foydalanuvchidan `.exe install`ni to'g'ridan-to'g'ri
ishga tushirib, xom xato xabarini so'radim.

## TO'QQIZINCHI marta topilgan xato: idempotentlik faqat VERSION solishtirar edi, xizmat mavjudligini tekshirmasdi

`USERDNSDOMAIN` xatosini tuzatgandan va Security Filtering muammosini
hal qilgandan keyin ham, foydalanuvchi qayta yoqilgandan keyin
`deploy.log`da **"Agent allaqachon eng so'nggi versiyada - hech
narsa qilinmadi"** ko'rdi, lekin `Get-Service` xizmat **umuman
mavjud emasligini** ko'rsatdi.

**ILDIZ SABAB**: avvalgi tuzatish jarayonida foydalanuvchiga
`NetworkSecurityAgent.exe remove` buyrug'ini bergandim (eski,
buzilgan xizmatni tozalash uchun) - bu buyruq **faqat Windows
Service ro'yxatidan o'chiradi**, `VERSION` faylini (va boshqa
fayllarni) **o'chirmaydi**. Natijada: `$InstallDir\VERSION` hali
ham "1.0.0" deb turardi, SYSVOL'dagi VERSION ham "1.0.0" - skript
"versiyalar bir xil, demak hammasi joyida" deb xulosa chiqarib,
xizmatni HECH QACHON qayta o'rnatmasdi - garchi xizmat aslida
**mavjud bo'lmasa ham**.

**Tuzatish**: idempotentlik tekshiruviga endi **xizmat haqiqatan
mavjudligi** (`Get-Service`) ham qo'shildi - faqat versiya bir xil
BO'LISHI YETARLI EMAS, xizmat ham aynan mavjud bo'lishi kerak. Agar
versiya bir xil, lekin xizmat yo'q bo'lsa, skript buni aniq
ogohlantirib, qayta o'rnatishni davom ettiradi.

`run_full_test.py`ga doimiy regressiya himoyasi qo'shildi.

**TO'QQIZINCHI MARTA TASDIQLANGAN SABOQ**: bu safar xato mening
o'zimning **oldingi tuzatish tavsiyam** (`remove` buyrug'i)ning
kutilmagan yon ta'siridan kelib chiqdi - bu shuni ko'rsatadiki, hatto
"vaqtinchalik" deb o'ylangan qo'lda buyruqlar ham keyingi avtomatik
mantiqqa ta'sir qilishi mumkin, va bunday holatlar faqat **haqiqiy,
ketma-ket, ko'p bosqichli production sinovi** orqaligina ochilib
qoladi.

## SAKKIZINCHI marta topilgan xato: GPO skriptida $env:USERDNSDOMAIN SYSTEM kontekstida ishonchsiz

Foydalanuvchi Domain Controller'da to'liq GPO oqimini (SYSVOL tayyorlash,
GPO yaratish, Startup Script bog'lash) bosqichma-bosqich bajarib,
**haqiqiy test kompyuterida qayta yoqish orqali** sinadi. `deploy.log`
faylini yuborganida:

**ILDIZ SABAB**: `Deploy-NetworkSecurityAgent.ps1`ning `param()`
blokida `$ServerShare` standart qiymati `$env:USERDNSDOMAIN`ga
to'g'ridan-to'g'ri bog'liq edi. GPO **Computer Startup Script**
foydalanuvchi hali login qilmasdan OLDIN, **SYSTEM** konteksti bilan
ishga tushadi - bu holatda `$env:USERDNSDOMAIN` (foydalanuvchi
sessiyasiga bog'liq muhit o'zgaruvchisi) **bo'sh qiymat** qaytardi.
Natijada `$ServerShare` domen nomisiz, buzilgan yo'lga aylanib,
`"VERSION topilmadi"` xatosi bilan deploy butunlay to'xtardi -
foydalanuvchining o'z `deploy.log` fayli buni aniq tasdiqladi
(birinchi, qo'lda/interaktiv urinishda ishlagan, lekin haqiqiy
avtomatik reboot'da muvaffaqiyatsiz bo'lgan - bu farq aynan SYSTEM
vs foydalanuvchi konteksti farqini ko'rsatadi).

**Tuzatish**: `param()` blokidan `$env:USERDNSDOMAIN` olib tashlandi,
buning o'rniga `[System.DirectoryServices.ActiveDirectory.Domain]::
GetCurrentDomain().Name` ishlatildi - bu kompyuterning AD'dagi domen
a'zoligidan to'g'ridan-to'g'ri o'qiydi, foydalanuvchi sessiyasiga
bog'liq emas, SYSTEM kontekstida (login'dan oldin ham) ishonchli
ishlaydi. `$env:USERDNSDOMAIN`ga faqat zaxira (fallback) sifatida
qaytiladi.

`run_full_test.py`ga doimiy regressiya himoyasi qo'shildi - `param()`
blokida `$env:USERDNSDOMAIN` to'g'ridan-to'g'ri qolmaganini va
`GetCurrentDomain()` ishlatilishini tekshiradi.

**SAKKIZINCHI MARTA TASDIQLANGAN SABOQ**: bu safar xato PowerShell/
Windows Service-ga xos, chuqur "kontekst farqi" muammosi edi (SYSTEM
vs interaktiv foydalanuvchi) - buni faqat foydalanuvchining haqiqiy,
to'liq GPO ish jarayonini (Domain Controller'dan tortib, haqiqiy
kompyuterni qayta yoqishgacha) sinab ko'rishi orqaligina aniqlash
mumkin edi.

## YETTINCHI marta topilgan xato turkumi: Suricata reader hech kim tomonidan chaqirilmagan

Foydalanuvchi "fayillarni tekshirmayabdi" muammosini davom ettirib,
fayl tekshirish uchun **ikkalasini ham** (Windows Agent + Suricata)
sozlashni so'radi. Suricata infratuzilmasini tekshirishda:

**ILDIZ SABAB**: `collectors/suricata_reader.py` to'g'ri yozilgan edi,
lekin `docker-compose.yml`da uni ishga tushiruvchi HECH QANDAY xizmat
yo'q edi (faqat `deep_scan_engine`ning `/var/log/suricata/files`
bind-mount'i bor edi - bu Suricata'ning ekstrakt qilingan fayllar
papkasi, `eve.json` emas). Bu - loyihada **yettinchi marta** uchragan
"kod to'g'ri, lekin hech kim uni ishga tushirmaydi" xato turkumi.

**Tuzatish**: yangi `suricata_reader` docker-compose xizmati -
host'dagi `/var/log/suricata/eve.json`ni faqat-o'qish rejimida
bog'laydi. `docs_SURICATA_SETUP.md`ga Docker integratsiyasi bo'limi
va muhim Docker nozik nuqtasi (fayl oldindan yaratilishi kerak, aks
holda Docker uni bo'sh papka sifatida yaratib qo'yishi mumkin)
qo'shildi.

**Real test qilingan (to'liq zanjir)**: haqiqiy Suricata `eve.json`
formatidagi test yozuvi bilan `suricata_reader.py --once` →
`FileEvent` yaratilishi → `file_analysis_engine.py` uni tekshirishi
to'liq real ishga tushirilib tasdiqlandi (fayl VirusTotal/MalwareBazaar
orqali "checked=True" bo'ldi - faqat sandbox internetga cheklangani
sabab "malicious" natijasi bo'lmadi, bu kutilgan cheklov).

**Bonus - real xato topildi va tuzatildi**: shu tekshiruv jarayonida
`read_existing()` funksiyasi HAR BIR fileinfo hodisasini (hatto
TAKRORIY bo'lsa ham) "qayta ishlangan" deb sanardi - `process_
fileinfo_event()` `bool` qaytaradigan qilib o'zgartirildi, `read_
existing()` faqat HAQIQATAN qo'shilgan yozuvlarni sanaydigan bo'ldi.

## OLTINCHI marta topilgan xato: API_SERVER_URL noto'g'ri protokol (https:// o'rniga http://)

Foydalanuvchi: "fayillarni tekshirmayabdi zararli zararsiz" - fayl
tekshirish ishlamayapti. Tekshirish jarayonida foydalanuvchining o'zi
`curl -sk https://172.16.1.206:8443/api/v1/check_hash` bilan sinaganida
**hech qanday javob (hatto xato ham) qaytmadi** - `-s` bayrog'i xatoni
yashirgan edi.

**ILDIZ SABAB**: `docker-compose.yml`dagi `gunicorn` HECH QANDAY SSL/
TLS sertifikatisiz oddiy HTTP orqali ishlaydi - lekin loyihaning **5
ta joyida** (`agent_core/agent.py`ning standart qiymati, ikkala GPO
PowerShell skripti, `docs_WINDOWS_AGENT_SETUP.md`, `docs_LINUX_AGENT_
SETUP.md`) `https://` yozilgan edi. Bu Windows/Linux Agent'larning
serverga ulanishini **jim ravishda, aniq xatosiz** muvaffaqiyatsiz
qilardi - fayl xeshlari hech qachon serverga yetmagan, shuning uchun
"fayllarni tekshirmayapti" degan taassurot paydo bo'lgan.

**Ikkinchi bo'shliq**: `API_SERVER_URL` `.env.example`da hech qachon
hujjatlashtirilmagan edi - foydalanuvchi buni sozlashi kerakligini
bilmagan bo'lardi.

**Tuzatish**: barcha 5 joy `http://`ga o'zgartirildi, `.env.example`ga
`API_SERVER_URL` qo'shildi (aniq izoh bilan: nega http, https emas),
`docs_WINDOWS_AGENT_SETUP.md`ga ochiq ogohlantirish qo'shildi.
`run_full_test.py`ga doimiy regressiya himoyasi qo'shildi - kelajakda
kimdir bexosdan `https://172.16.0.5:8443`ni qaytarsa, test darhol
ushlaydi.

**OLTINCHI MARTA TASDIQLANGAN SABOQ**: foydalanuvchining o'z qo'lda
ishga tushirgan `curl` buyrug'i (hatto **muvaffaqiyatsiz**, natija
bermagan bo'lsa ham) yana bir marta faqat production muhitida
ochiladigan real xatoni fosh qildi.

## BESHINCHI marta topilgan xato turkumi: UniFi ma'lumoti hali ham Dashboard'da ko'rinmasdi

Foydalanuvchi: "unifi controllerdan olingan ma'lumotlar dashbordda
ko'rinmayabdi" - avvalgi tuzatishimdan (`discover_via_unifi()`)
KEYIN ham. Sabab ikki qatlamli edi:

1. `docker-compose.yml`dagi yagona `discover_via_unifi()`ni chaqiruvchi
   xizmat (`network_discovery`) `profiles: ["discovery"]` bilan
   belgilangan edi - foydalanuvchining oddiy `docker compose up -d`
   buyrug'i bilan HECH QACHON ishga tushmagan.
2. Hatto ishga tushsa ham, o'sha xizmatning ichidagi kod
   (`scheduler.py`) UniFi'ni umuman chaqirmasdi - faqat ARP/ICMP.

**Tuzatish**: UniFi uchun ALOHIDA, `network_discovery/unifi_sync_
loop.py` - bu HECH QANDAY host tarmoq yoki maxsus huquq talab
qilmaydi (shunchaki HTTPS API so'rovi), shuning uchun yangi
`unifi_sync` docker-compose xizmati **PROFILSIZ** (standart `docker
compose up -d` bilan avtomatik ishga tushadigan) qilib qo'shildi.

**Real test qilingan**: docker-compose.yml'da profilsiz ekanligi
tasdiqlangan + real HTTP orqali sinxronizatsiya (DB'ga yozish) va
UniFi sozlanmagan holatda xato bermasligi tekshirildi.

**Beshinchi marta tasdiqlangan saboq**: "funksiya to'g'ri ishlaydi"
bilan "funksiya production'da haqiqatan ishga tushadi" - ikki
BUTUNLAY BOSHQA savol. Bu safar bo'shliq HATTO oldingi maxsus
tuzatishdan (a4489ef) keyin ham qolib ketgan edi - chunki men
funksiyaning o'zini test qilgandim, lekin uni ChAQIRUVCHI
infratuzilma (docker-compose profil sozlamasi) qatoriga yetarlicha
chuqur bormagandim.

## Dashboard mahalliy vaqt zonasi (+5:00, Toshkent)

Foydalanuvchi so'radi: "vaqt farqini ham yuqot bizning mintaqa +5:00".

**Arxitektura qarori**: bazada BARCHA vaqt belgilari UTC formatida
saqlanadi (turli manbalardan - Suricata, Windows Event Log, syslog -
kelayotgan loglarni to'g'ri solishtirish/korrelyatsiya qilish uchun
bu standart SIEM amaliyoti). `TIMEZONE_OFFSET_HOURS` (standart 5)
sozlamasi FAQAT Dashboard'da FOYDALANUVCHIGA ko'rsatishda qo'llaniladi.

Qurilgan:
- `dashboard/app.py`: yangi `local_dt` Jinja2 filtri - UTC datetime'ni
  mahalliy vaqtga o'tkazib formatlaydi, `None` holatini xavfsiz
  boshqaradi.
- 8 ta shablon fayldagi barcha 11 ta `.strftime()` chaqiruvi
  `local_dt` filtriga almashtirildi (alerts, api_tokens,
  asset_inventory, audit, devices, files, index, users).
- `config/settings.py`: `TIMEZONE_OFFSET_HOURS` sozlamasi.
- `Dockerfile`: `tzdata` paketi qo'shildi (konteyner darajasidagi
  `TZ=Asia/Tashkent` nomli qiymatlarning to'g'ri ishlashi uchun).

**Real test qilingan**: filtr to'g'ridan-to'g'ri (+5 soat, None,
maxsus format) va **to'liq real HTTP orqali** (bazaga UTC 08:30:00
yozib, Dashboard'da aynan 13:30:00 ko'rinishini, xom UTC vaqt hech
qachon ko'rinmasligini tasdiqlash) tekshirildi.

## Avtomatik bloklash zanjirini to'liq tasdiqlash + connection_type xatosi

Foydalanuvchi so'radi: "UniFi orqali wirusli fayl yuklab olganini
tekshirish va agar virusli fayl bo'lsa IP'ni bloklash imkonini qilsa
bo'ladimi?" - tekshirilganda, infratuzilma (`response_engine.py` +
`adapter_registry.py` + `UniFiAdapter`) **allaqachon to'g'ri ulangan**
edi, lekin buni tekshirish jarayonida **real xato topildi**:

`discover_via_unifi()` simli klientlarni `connection_type="wired"` deb
belgilar edi, lekin `SwitchSNMPAdapter.can_handle()` `"cable"`ni kutadi
- bu satr nomuvofiqligi simli UniFi qurilmalarini **hech qanday
adapter tomonidan tanilmaydigan, "himoyasiz"** holatga keltirar edi.
`"wired"` -> `"cable"`ga tuzatildi. (Simli UniFi klientlari uchun
to'liq avtomatik bloklash hali ham `switch_port` yetishmagani sabab
ishlamaydi - bu alohida, kelajakdagi ish, halol izohlangan.)

**Real end-to-end test qilingan (Wi-Fi holat uchun, ko'pchilik holat)**:
UniFi orqali qurilma kashf qilinadi -> virusli fayl alerti (severity=
critical) yaratiladi -> Response Engine avtomatik ishga tushadi ->
**UniFi serverining o'ziga haqiqiy HTTP bloklash so'rovi yetib boradi**
(soxta server orqali tasdiqlangan) -> `alert.action_taken`da
"AVTOMATIK CHORA: UniFi... muvaffaqiyatli bajarildi" ko'rinadi.

**Javob foydalanuvchiga**: HA, bu funksiya allaqachon mavjud va ishlab
turibdi - Wi-Fi orqali ulangan qurilmalar uchun to'liq avtomatik.

## UniFi -> Asset Inventory integratsiya bo'shlig'i (to'rtinchi real production topilma)

Foydalanuvchi: "unifi os controllerdan olindan malumotlar dashbord da
ko'rinmayabdi" (Dashboard'ni to'g'ri xato bermayotganini, `get_unifi_
clients()`ni to'g'ridan-to'g'ri chaqirganda 207 ta klient qaytishini
tasdiqlagandan keyin).

**Ildiz sabab**: `network_discovery/unifi_discovery.py`ning `get_unifi_
clients()` funksiyasi to'g'ri ishlar edi, lekin loyihaning HECH QANDAY
joyida haqiqatan CHAQIRILMAGAN edi (faqat izohlarda tilga olingan) -
`network_discovery/asset_inventory.py` (bazaga yozuvchi markaziy
modul) UniFi'ni umuman bilmas edi. Shuning uchun UniFi ma'lumoti hech
qachon `devices` jadvaliga yozilmagan, Dashboard'da ko'rinishi mumkin
emas edi.

**Tuzatish**: `asset_inventory.py`ga `discover_via_unifi()` qo'shildi
(UniFi klientlarini olib, DB'ga yozadi - IP'siz klientlar to'g'ri
o'tkazib yuboriladi), `full_discovery()`ga integratsiya qilindi
(`UNIFI_CONTROLLER_URL` sozlangan bo'lsa avtomatik), va CLI'ga
`--unifi-only` bayrog'i qo'shildi (faqat UniFi'dan, ARP/ICMP tarmoq
interfeysisiz).

**Real test**: to'liq zanjir (soxta UniFi server -> `discover_via_
unifi()` -> real DB yozuvi -> Dashboard `/asset-inventory` sahifasida
haqiqatan ko'rinishi) tasdiqlangan.

**To'rtinchi marta tasdiqlangan saboq**: foydalanuvchining "funksiya
to'g'ri ishlaydi, lekin natija ko'rinmayapti" degan real kuzatuvi -
funksiyaning o'zi to'g'ri bo'lsa ham, uni **hech kim chaqirmasligi**
mumkinligini (integratsiya bo'shlig'i) ochib berdi. Bu turdagi xato
alohida unit-testlarda (masalan "UniFi API Key integratsiyasi" testi)
umuman ko'rinmaydi, chunki ular funksiyani to'g'ridan-to'g'ri
chaqiradi - end-to-end (CLI/Dashboard'dan boshlab) test kerak edi.

## Avtomatik ustun-migratsiya - real production xatosi orqali topilgan tizimli bo'shliq

Foydalanuvchi haqiqiy Dashboard xatosini (`Internal Server Error`) va
uning `docker compose logs dashboard` chiqishini yubordi:
`sqlalchemy.exc.ProgrammingError: column devices.agent_last_heartbeat
does not exist`.

**Ildiz sabab**: `db/models.py`dagi `init_db()` faqat `Base.metadata.
create_all()` chaqirar edi - bu FAQAT yangi jadvallarni yaratadi,
MAVJUD jadvallarga yangi ustun hech qachon qo'shmaydi. Loyiha oylar
davomida rivojlanib, `Device` jadvaliga turli bosqichlarda 10 ta yangi
ustun (`risk_score`, `device_type`, `agent_last_heartbeat` va h.k.)
qo'shilgan, lekin foydalanuvchining bazasi ancha oldin (bu ustunlar
mavjud bo'lmagan paytda) yaratilgan edi - loyihada rasmiy migratsiya
vositasi (Alembic) yo'q edi.

**Tuzatish**: `_sync_missing_columns()` funksiyasi qo'shildi -
`create_all()`dan keyin har bir jadvalning ORM modelida e'lon
qilingan ustunlarini haqiqiy bazadagilar bilan solishtiradi, va
yetishmayotgan (faqat NULLABLE - xavfsizlik uchun) ustunlarni
avtomatik `ALTER TABLE ... ADD COLUMN` orqali qo'shadi. NOT NULL
ustun yetishmasa, jim qoldirilmaydi - aniq ogohlantirish bilan
o'tkazib yuboriladi (qo'lda hal qilish talab etiladi).

**Real test qilingan**: eski sxema (ustunlar yo'q, real ma'lumot
bilan) qo'lda yaratilib, yangi kod bilan `init_db()` chaqirilganda -
**ham SQLite'da, ham HAQIQIY PostgreSQL'da** (bu sandbox'ga maxsus
o'rnatilib) barcha 10 ustun to'g'ri turlar bilan qo'shilgani, mavjud
ma'lumot to'liq saqlanib qolgani, va ORM so'rovi (aynan Dashboard
xato bergan turi) endi xatosiz ishlashi tasdiqlandi. Ikkinchi marta
chaqirilganda ham xatosiz (idempotent) ekanligi tekshirildi.

**MUHIM saboq (uchinchi marta)**: bu loyihada foydalanuvchining
haqiqiy production muhitidan olingan ma'lumot (1-UniFi/AD ruxsatlari,
2-UniFi paginatsiya, 3-bu migratsiya xatosi) yana bir marta sof
mock/test muhitida hech qachon ochilmaydigan tizimli xatoni aniqladi.

## UniFi paginatsiya xatosi - foydalanuvchining real production ma'lumoti orqali topildi

Foydalanuvchi `curl` orqali haqiqiy UniFi Integration API javobini
yubordi: `"count":25,"totalCount":195` - bu mening kodim **faqat
birinchi 25 ta klientni olib, qolgan ~170 tasini jimgina yo'qotib
qo'yayotganini** ochib berdi (API natijalarni sahifalab qaytaradi,
mening kodim esa sahifalashni umuman hisobga olmagan edi).

Tuzatildi: `network_discovery/unifi_discovery.py`ga to'liq paginatsiya
tsikli qo'shildi (`offset`ni oshirib, `totalCount`ga yetguncha davom
etadi, maksimal 50 sahifa xavfsizlik chegarasi bilan).

**Real test** (soxta server orqali): eng qiyin holat - server mening
so'ragan `limit=200`ni E'TIBORSIZ qoldirib, har doim majburiy 25/30
tadan qaytarsa ham - barcha yozuvlar (195 va alohida 73 ta test bilan)
to'g'ri, takrorsiz yig'ib olinishi tasdiqlandi (8 va 3 ta ketma-ket
HTTP so'rov orqali, `offset`lar aniq nazorat qilindi).

Shuningdek `ap_mac` maydoni `uplink_device_id`ga o'zgartirildi - real
API javobida bu MAC manzil emas, balki qurilma UUID'si ekanligi
aniqlandi (`uplinkDeviceId: "3fe055db-580c-3ea6-bc10-5a88e0f71fe8"`).

**MUHIM saboq**: bu loyihada **ikkinchi marta** foydalanuvchining
haqiqiy production muhitidan olingan real ma'lumot (birinchisi - GPO
ruxsatlari) kod yozuvchisi (men) uchun mavjud bo'lmagan sinov
sharoitini (195 ta real UniFi klienti) ochib berdi va jiddiy xatoni
aniqladi. Bu sinf xatolar faqat sof mock/soxta ma'lumot bilan
sinalganda ko'p hollarda yashiringan qoladi.

## UniFi API Key integratsiyasi (foydalanuvchining production so'rovi)

Foydalanuvchi haqiqiy UniFi Controller manzilini berdi
(`172.16.0.64:11443`) va API Key asosida integratsiya qilishni so'radi
(login/parol o'rniga - `UNIFI_API_KEY`, `UNIFI_SITE_ID` UUID
ko'rinishida, `UNIFI_VERIFY_SSL`, `UNIFI_POLL_INTERVAL`).

Web qidiruv orqali (bir nechta mustaqil manba, jumladan rasmiy
Ubiquiti Help Center) UniFi'ning **yangi Integration API (v1)**
tuzilishi tasdiqlandi: login bosqichisiz, `X-API-Key` sarlavhasi
orqali, manzil `{controller}/proxy/network/integration/v1/...`, sayt
NOMI emas UUID orqali.

Qurilgan:
- `network_discovery/unifi_discovery.py` - API Key ASOSIY usul,
  login/parol ZAXIRA usul (agar API Key muvaffaqiyatsiz bo'lsa).
- `response/unifi_adapter.py` - bloklash/uzish uchun ham xuddi shu
  ustuvorlik (API Key -> muvaffaqiyatsiz bo'lsa avtomatik legacy).
  MUHIM (halol izoh): block/kick amal nomlari yangi Integration
  API'da hali to'liq rasmiy hujjatlashtirilmagan ("Early Access", 2025)
  - shuning uchun bu yerda ayniqsa zaxira mexanizmi muhim.

**Real test qilingan**: ikkalasi ham HAQIQIY HTTP (Flask soxta server,
UniFi Integration API'ni to'liq taqlid qiluvchi) orqali - 4 stsenariy:
to'g'ri API Key (klientlar ro'yxati + bloklash), noto'g'ri API Key
(graceful fail), va eng muhimi - **API Key muvaffaqiyatsiz bo'lganda
avtomatik legacy usulga o'tish** (barchasi tasdiqlangan).

**Muhim dizayn qarori**: barcha UniFi muhit o'zgaruvchilari funksiya
ichida DINAMIK o'qiladi (modul darajasidagi konstanta emas) - bu
loyihada bir necha marta uchragan xato turkumini oldindan oldini oldi.

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
