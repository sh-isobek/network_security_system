# TLS + Ichki CA (va ixtiyoriy mTLS) sozlash — xavfsizlik auditi (CRITICAL)

## 1. Nima o'zgardi

Ilgari `agent_api` (8443) va `dashboard` (8080) xizmatlari oddiy HTTP
orqali ishlar edi (Windows/Linux/Mac Agent'lar va Dashboard
brauzerlari trafigi **shifrlanmagan** LAN orqali o'tardi). Endi bitta
yangi `nginx` xizmati (docker-compose.yml) TLS termination'ni
bajaradi:

```
[Agent/brauzer] --HTTPS(TLS)--> [nginx :8443/:8843] --HTTP(faqat Docker ichki tarmog'i)--> [agent_api :8443 / dashboard :8080]
```

`agent_api`/`dashboard`ning o'zi hamon TLS bilmaydi (soddaligicha
qoladi), lekin ular endi FAQAT `127.0.0.1`ga bog'langan - LAN'dan
to'g'ridan-to'g'ri erishib bo'lmaydi, faqat `nginx` orqali.

Sertifikatlar **ichki, korxona uchun o'z-o'zidan yaratilgan CA**
tomonidan imzolanadi (jamoat CA'siga - Let's Encrypt va h.k. - ehtiyoj
yo'q, chunki bu faqat ichki `172.16.0.0/22` tarmog'ida ishlaydi).

## 2. Ichki CA va server sertifikatini yaratish

```bash
TLS_SERVER_HOSTNAMES="security-agent-api.company.local,dashboard.company.local" \
TLS_SERVER_IPS="172.16.1.206" \
bash deploy/pki/generate_ca.sh
```

Natija: `deploy/pki/certs/ca.crt` (+ `ca.key`), `server.crt` (+
`server.key`). **`ca.key`/`server.key` HECH QACHON git'ga
commit qilinmaydi** (`.gitignore`'da `deploy/pki/certs/` butunlay
istisno qilingan).

- `TLS_SERVER_HOSTNAMES`/`TLS_SERVER_IPS` - Agent'lar/brauzerlar
  ulanadigan HAQIQIY manzil(lar) bo'lishi SHART (Subject Alternative
  Name sifatida sertifikatga kiritiladi) - aks holda TLS tekshiruvi
  "hostname mos kelmadi" bilan rad etiladi.
- Skript **idempotent**: CA allaqachon mavjud bo'lsa qayta
  yaratilmaydi (aks holda barcha tarqatilgan Agent'lar ishonchini
  yo'qotib qo'yardi) - faqat server sertifikati (SAN o'zgargan/muddati
  o'tgan bo'lsa) yangilanadi.

## 3. Agent/brauzer tomonida CA'ga ishonish

**Windows Agent** (`agent_core/agent.py`): `.env`ga (yoki SYSVOL orqali
tarqatiladigan muhit o'zgaruvchisiga) qo'shing:

```
API_SERVER_URL=https://security-agent-api.company.local:8443
AGENT_CA_BUNDLE_FILE=C:\ProgramData\NetworkSecurityAgent\ca.crt
```

`ca.crt`ni GPO orqali SYSVOL'dan (masalan `Deploy-
NetworkSecurityAgent.ps1`ning `Read-DotEnv` mexanizmiga o'xshab)
har bir kompyuterga nusxalash tavsiya etiladi. `AGENT_CA_BUNDLE_FILE`
bo'sh qoldirilsa, agent standart tizim ishonch do'koniga tayanadi -
bu holda CA'ni Windows'ning **Trusted Root Certification Authorities**
do'koniga GPO orqali o'rnatish kerak bo'ladi.

**MUHIM**: kod HECH QACHON `verify=False` ishlatmaydi (bu MITM
hujumiga to'liq ochiq bo'lardi) - CA yo'qligida standart tekshiruv
davom etadi va agar server sertifikati ishonchsiz bo'lsa, so'rov
xato bilan rad etiladi (aynan shu narsa xavfsizlik uchun kerak).

**Dashboard brauzerlari**: `ca.crt`ni operatsion tizim/brauzerning
ishonchli sertifikatlar do'koniga (yoki GPO orqali barcha kompyuterlarga
markazlashtirilgan) qo'shing - aks holda brauzer "ishonchsiz
sertifikat" ogohlantirishini ko'rsatadi (funksional jihatdan hamon
ishlaydi, faqat ogohlantirish bilan).

## 4. docker-compose

`.env`ga hech narsa qo'shish shart emas (standart qiymatlar ishlaydi),
lekin ixtiyoriy sozlanadigan narsalar:

```
TLS_SERVER_HOSTNAMES=security-agent-api.company.local,dashboard.company.local
TLS_SERVER_IPS=172.16.1.206
AGENT_MTLS_REQUIRED=false
```

`docker compose up -d` - `nginx` xizmati avtomatik (profilsiz)
ishga tushadi, `deploy/pki/certs/`ni faqat-o'qish rejimida o'qiydi.
**Muhim**: `docker compose up`dan OLDIN `generate_ca.sh`ni qo'lda bir
marta ishga tushirish kerak (nginx sertifikat fayllari mavjud bo'lishini
kutadi, o'zi yaratmaydi).

Portlar: **8443** (Agent API, TLS) va **8843** (Dashboard, TLS) -
ikkalasi ham `0.0.0.0`ga bog'langan (LAN'ga OCHIQ - bu TLS termination
qatlamining butun maqsadi). `agent_api`/`dashboard`ning o'z portlari
(8443/8080) hamon `127.0.0.1`ga bog'langan (faqat host'dan debug
uchun, LAN'ga OCHIQ EMAS).

## 5. Ixtiyoriy: mTLS (client sertifikat) Agent API uchun

Standart holatda **O'CHIQ** - Agent autentifikatsiyasi mavjud
per-agent API token (`X-API-Key`) orqali ishlayveradi, bu allaqachon
yetarlicha kuchli. mTLS **qo'shimcha** himoya qatlami (masalan token
o'g'irlangan taqdirda ham, hujumchida haqiqiy client sertifikat
bo'lmasa so'rov TLS darajasidayoq rad etiladi).

Yoqish:

```bash
# 1) Har bir Agent kompyuteri uchun alohida client sertifikat:
bash deploy/pki/issue_agent_cert.sh WIN10-PC-042

# 2) .env'da yoqish:
echo "AGENT_MTLS_REQUIRED=true" >> .env
docker compose up -d nginx   # nginx'ni qayta yuklash

# 3) Agent tomonida (.env yoki SYSVOL):
AGENT_TLS_CLIENT_CERT_FILE=C:\ProgramData\NetworkSecurityAgent\WIN10-PC-042.crt
AGENT_TLS_CLIENT_KEY_FILE=C:\ProgramData\NetworkSecurityAgent\WIN10-PC-042.key
```

`AGENT_MTLS_REQUIRED=true` bo'lganda, client sertifikatsiz (yoki
ishonchsiz sertifikat bilan) kelgan HAR QANDAY so'rov nginx tomonidan
HTTP 400 bilan rad etiladi - `agent_api`ning o'ziga hech qachon
yetib bormaydi. Dashboard (8843) mTLS talab qilmaydi - foydalanuvchilar
oddiy brauzer orqali, login/parol (+ ixtiyoriy MFA) bilan kiraveradi.

## 6. Halol cheklovlar

- `ssl_protocols TLSv1.2 TLSv1.3` nginx'da sozlangan (eski, zaif
  protokollar rad etiladi), lekin bu sandbox test muhitida (OpenSSL 3,
  legacy protokollar client tomonda allaqachon o'chirilgan) to'liq
  server-tomon rad etishni alohida sinash imkonsiz bo'ldi - direktivaning
  o'zi standart, keng qo'llaniladigan nginx sintaksisi.
- Sertifikat **avtomatik yangilanish/rotatsiya** (masalan cron orqali)
  hali yo'q - `server.crt` ~27 oy, client sertifikatlar ~13 oy muddatli
  (`deploy/pki/generate_ca.sh`dagi `TLS_SERVER_DAYS`/`TLS_CLIENT_DAYS`
  orqali sozlanadi) - muddat tugashidan oldin qo'lda qayta ishga
  tushirish kerak bo'ladi.
- mTLS yoqilganda ham, Agent kompyuterida sertifikat/kalit fayli
  himoyalangan joyda saqlanishi (masalan faqat LocalSystem o'qiy
  oladigan ACL) administratorning o'z mas'uliyati - bu hali GPO
  skriptiga avtomatlashtirilgan holda ulanmagan (kelajakdagi ish).

## 7. Real test qilingan

`run_full_test.py`dagi "XAVFSIZLIK (CRITICAL): TLS reverse proxy"
testi **hech narsani soxtalashtirmaydi**:

- Haqiqiy `deploy/pki/generate_ca.sh`/`issue_agent_cert.sh` (real
  `openssl` chaqiruvlari orqali CA/server/client sertifikat).
- Haqiqiy `api.server`/`dashboard.app` - alohida jarayonda ishlaydigan
  Flask server (test_client emas, real TCP/HTTP).
- Haqiqiy `nginx` binary + production'da ishlatiladigan **aynan shu**
  `deploy/nginx/entrypoint.sh` (nusxa emas).

Tekshirilgan stsenariylar: to'g'ri CA bilan Agent API/Dashboard'ga
HTTPS orqali muvaffaqiyatli ulanish; ichki CA'ga ishonmagan so'rov
SSL xatosi bilan rad etilishi; `check_hash`ning haqiqiy TLS orqali
ishlashi; mTLS yoqilganda client sertifikatsiz/ishonchsiz sertifikat
bilan so'rov HTTP 400 bilan rad etilishi; CA tomonidan imzolangan
haqiqiy client sertifikat bilan muvaffaqiyatli o'tishi; mTLS
yoqilganda ham Dashboard'ning oddiy TLS bilan ishlashda davom etishi.

Ham SQLite, ham PostgreSQL'da tasdiqlangan.
