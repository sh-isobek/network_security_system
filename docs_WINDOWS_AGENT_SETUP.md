# Windows Endpoint Agent — o'rnatish yo'riqnomasi (6-bosqich)

## Arxitektura

```
[Windows PC]                                    [Markaziy Server]
  Endpoint Agent (Windows Service)
    - Downloads/Desktop/Temp kuzatiladi
    - Yangi fayl -> SHA256 hisoblash
    - -----POST /api/v1/check_hash------------>  api/server.py (Flask)
    - <----{"malicious": true/false}------------      |
    - Zararli bo'lsa:                                  v
        - Jarayonni to'xtatish (psutil)          db/models.py (HashBlacklist,
        - Faylni o'chirish                        Alert, Device)
    - -----POST /api/v1/report_incident-------->      |
                                                        v
                                              engine/response_engine.py
                                              (agar kerak bo'lsa qo'shimcha
                                               tarmoq darajasidagi chora)
```

## 1. Markaziy serverni ishga tushirish

Server allaqachon tarmoq monitoring tizimi bilan bir joyda ishlaydi:

```bash
export AGENT_API_KEY="<kuchli-tasodifiy-kalit>"
python -m api.server
```

**MUHIM (production):** 
- Development server (`flask run`) production uchun mos emas - `gunicorn`
  yoki `waitress` orqali ishga tushiring:
  ```bash
  pip install gunicorn
  gunicorn -w 4 -b 0.0.0.0:8443 api.server:app
  ```
- HTTPS albatta yoqilishi kerak (ichki CA sertifikati bilan) - aks holda
  `AGENT_API_KEY` tarmoqda ochiq matn holida uzatiladi.
- `AGENT_API_KEY`ni `.env` fayliga yozing, kodda hardcode qilmang.

## 2. Windows kompyuterlarga agentni o'rnatish

### a) Python o'rnatish (agar yo'q bo'lsa)

Windows kompyuterlarga Python 3.10+ o'rnatilishi kerak (yoki agentni
`PyInstaller` bilan yagona `.exe` faylga aylantirish mumkin - pastda).

### b) Kerakli fayllarni nusxalash

`windows_agent/`, `config/` papkalarini va `requirements-agent.txt`ni
Windows kompyuterga nusxalang (masalan Group Policy orqali barcha
kompyuterlarga bir vaqtda tarqatish mumkin).

### c) Kutubxonalarni o'rnatish

```powershell
pip install watchdog psutil requests pywin32
```

### d) Sozlash (muhit o'zgaruvchilari)

**YANGILANDI (xavfsizlik auditi, CRITICAL)**: server endi `nginx`
xizmati orqali HAQIQIY TLS bilan ishlaydi (ichki CA tomonidan
imzolangan sertifikat - `docs_TLS_SETUP.md`ga qarang). Shuning uchun
endi **`https://` ishlatiladi** (avvalgi versiyalarda TLS umuman
sozlanmagani uchun `http://` tavsiya etilgan edi - bu endi ESKIRGAN).
Agent CA'ga ishonishi uchun `AGENT_CA_BUNDLE_FILE`ni ham sozlang
(yoki CA'ni Windows'ning Trusted Root do'koniga GPO orqali o'rnating).

```powershell
setx API_SERVER_URL "http://172.16.0.5:8443"
setx AGENT_API_KEY "<markazdagi bilan bir xil kalit>"
setx AGENT_CA_BUNDLE_FILE "C:\ProgramData\NetworkSecurityAgent\ca.crt"
```

### e) Windows Service sifatida o'rnatish

```powershell
python windows_agent\service_wrapper.py install
python windows_agent\service_wrapper.py start
```

Endi agent kompyuter yoqilishi bilan avtomatik ishga tushadi, foydalanuvchi
login qilmagan bo'lsa ham ishlayveradi.

### f) Tekshirish

```powershell
python windows_agent\service_wrapper.py status
```

Windows "Services" (services.msc) oynasida "Network Security Endpoint
Agent" nomi bilan ko'rinishi kerak.

## 3. .exe fayl sifatida tarqatish (ixtiyoriy, tavsiya etiladi)

Har bir kompyuterga Python o'rnatish shart bo'lmasligi uchun:

```powershell
pip install pyinstaller
pyinstaller --onefile --name NetworkSecurityAgent windows_agent\agent.py
```

Natijada `dist\NetworkSecurityAgent.exe` - buni Group Policy yoki SCCM
orqali barcha kompyuterlarga avtomatik tarqatish mumkin.

## 4. Kuzatiladigan papkalar (standart)

`windows_agent/agent.py` ichida standart ravishda quyidagilar kuzatiladi:
- `%USERPROFILE%\Downloads`
- `%USERPROFILE%\Desktop`
- `%TEMP%`
- `%LOCALAPPDATA%\Microsoft\Outlook` (Outlook email ilovalari shu yerga
  vaqtincha saqlanadi)

Boshqa papka qo'shish uchun `--watch-dirs` argumentini ishlating yoki
`_default_watch_dirs()` funksiyasini tahrirlang.

## 5. Active Directory orqali avtomatik tarqatish (GPO)

Yuqoridagi 2-bo'lim **bitta kompyuterda qo'lda** o'rnatishni tasvirlaydi.
Domenga a'zo ko'p sonli kompyuterlar uchun (masalan 50, 200, 1000+)
buni **Group Policy Object (GPO)** orqali butunlay avtomatlashtirish
mumkin - foydalanuvchi hech narsa qilmasdan, kompyuter domenga
ulanganida (yoki keyingi reboot'da) agent avtomatik o'rnatiladi.

**MUHIM**: bu bo'lim endi mustaqil `NetworkSecurityAgent.exe` faylidan
foydalanadi - domendagi kompyuterlarda Python o'rnatilgan bo'lishi
SHART EMAS. `.exe` GitHub Actions orqali avtomatik quriladi
(pastga qarang, 5.1-bo'lim).

### 5.1. `.exe` faylini olish

`.exe` GitHub'ning **haqiqiy Windows runner'ida** avtomatik quriladi
(`.github/workflows/build-windows-agent.yml`) - `windows_agent/`,
`agent_core/` yoki `requirements-agent.txt` o'zgargan har safar.

**Yuklab olish**:
1. `https://github.com/sh-isobek/network_security_system/actions/workflows/build-windows-agent.yml`
   sahifasiga o'ting
2. Eng so'nggi muvaffaqiyatli (yashil ✅) ishga tushirishni tanlang
3. **"Artifacts"** bo'limidan `NetworkSecurityAgent-X.Y.Z.zip`ni
   yuklab oling

Bu arxiv ichida: `NetworkSecurityAgent.exe`, `VERSION`,
`Deploy-NetworkSecurityAgent.ps1`, `Install-NetworkSecurityAgent.ps1`.

**Qo'lda ham qurish mumkin** (agar Windows kompyuteringiz bo'lsa):
```powershell
pip install -r requirements-agent.txt pyinstaller
pyinstaller windows_agent\build\NetworkSecurityAgent.spec
# Natija: dist\NetworkSecurityAgent.exe
```

### 5.2. Qanday ishlaydi

```
[Domain Controller]                    [Har bir Windows PC]
  SYSVOL\...\scripts\
    NetworkSecurityAgent\
      NetworkSecurityAgent.exe   ──►   Kompyuter yoqiladi
      VERSION                            │
      .env                               ▼
        (API_SERVER_URL=...       GPO Startup Script ishga tushadi
         AGENT_API_KEY=...)         (SYSTEM huquqi bilan, login'dan oldin)
                                          │
                                    Versiya solishtiradi:
                                    o'rnatilgan == mavjud?
                                      │           │
                                     HA           YO'Q
                                      │           │
                                  Chiqadi    .exe'ni nusxalaydi,
                                  (jim)      HAR KOMPYUTER uchun ALOHIDA
                                             API token so'raydi
                                             (/api/v1/agent_enroll),
                                             xizmatni o'z 'install'
                                             buyrug'i orqali
                                             o'rnatadi/yangilaydi
```

**MUHIM (versiya yangilanishida qayta sozlash shart emas)**: `.env` —
SYSVOL'da **alohida, doimiy** fayl (`.env.example` bilan bir xil
format: `API_SERVER_URL=...` va `AGENT_API_KEY=...` qatorlari). Siz
uni **FAQAT BIR MARTA** yaratasiz — `NetworkSecurityAgent.exe`
va `Deploy-NetworkSecurityAgent.ps1` qancha marta yangilansa ham (masalan
`docs`dagi keyingi tuzatishlar orqali), bu faylga **hech qachon
tegilmaydi**. Deploy skripti har doim uni SYSVOL'dan o'qiydi va
skriptning o'z ichidagi standart qiymatlaridan **ustun** qo'yadi.
(Eski, ikkita alohida fayl — `api_key.secret` va `api_server_url.txt`
— hali ham qo'llab-quvvatlanadi: agar `.env` topilmasa, ularga
qaytiladi, shuning uchun avvalgi sozlashni yangilash SHART EMAS.)

**MUHIM (yangi funksiya — har kompyuter uchun alohida API token)**:
`.env`dagi `AGENT_API_KEY` endi faqat **bootstrap** (dastlabki ishonch)
kalit sifatida ishlatiladi. Har bir kompyuter birinchi marta ishga
tushganda, Deploy skripti markaziy serverdan (`POST /api/v1/agent_enroll`)
SHU KOMPYUTERGA ALOHIDA tegishli API token so'raydi va uni mahalliy
(`C:\ProgramData\NetworkSecurityAgent\agent_api_token.secret`) saqlaydi
— shundan keyin xizmat umumiy bootstrap kalit o'rniga SHU tokenni
ishlatadi. Bu tokenlar Dashboard'ning **"API Tokenlar"** sahifasida
(`/api-tokens`, faqat admin) ko'rinadi va kerak bo'lsa alohida bekor
qilinishi (revoke) mumkin — masalan bitta kompyuter yo'qolgan/
buzilgan bo'lsa, faqat O'SHA kompyuterning tokenini bekor qilish
kifoya, umumiy bootstrap kalitni o'zgartirish shart emas.

### 5.3. Sozlash qadamlari

**a) SYSVOL'da agent paketini tayyorlash** (Domain Controller'da):

```powershell
$SysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\scripts\NetworkSecurityAgent"
New-Item -ItemType Directory -Path $SysvolPath -Force

# 5.1-bo'limda yuklab olingan/qurilgan arxivdan:
Copy-Item -Path "C:\Downloads\NetworkSecurityAgent-1.0.0\NetworkSecurityAgent.exe" -Destination $SysvolPath
Copy-Item -Path "C:\Downloads\NetworkSecurityAgent-1.0.0\VERSION" -Destination $SysvolPath

# Server manzili va bootstrap API kalitini BITTA `.env` fayliga
# (bu fayl uchun ACL orqali faqat "Domain Computers" guruhiga
# O'QISH huquqini bering, boshqa hech kimga) - BIR MARTA yaratiladi,
# keyingi versiya yangilanishlarida bu faylga tegilmaydi.
@"
API_SERVER_URL=https://<Ubuntu-server-IP>:8443
AGENT_API_KEY=<markazdagi AGENT_API_KEY bilan bir xil>
AGENT_CA_BUNDLE_FILE=C:\ProgramData\NetworkSecurityAgent\ca.crt
"@ | Set-Content -Path "$SysvolPath\.env"

# ca.crt'ni ham shu SYSVOL papkasiga qo'ying (deploy/pki/certs/ca.crt,
# generate_ca.sh orqali yaratilgan) - Deploy-NetworkSecurityAgent.ps1
# uni har kompyuterga nusxalaydi (docs_TLS_SETUP.md'ga qarang).
Copy-Item -Path "\\path\to\repo\deploy\pki\certs\ca.crt" -Destination $SysvolPath
```

**Yangilanish chiqarganda** (masalan versiya 1.1.0): yangi `.exe`ni
yuklab oling, `$SysvolPath`dagi eskisini almashtiring, va
`VERSION` faylini yangi raqamga o'zgartiring - GPO Startup Script
bu farqni avtomatik payqab, barcha kompyuterlarni keyingi
reboot'da yangilaydi. **`.env` fayliga tegishning HOJATI YO'Q** -
u alohida, doimiy konfiguratsiya, `.exe`/`Deploy-NetworkSecurityAgent.ps1`
versiyasidan mustaqil.

**b) Deploy skriptini SYSVOL'ga qo'yish**:

```powershell
Copy-Item -Path "C:\Downloads\NetworkSecurityAgent-1.0.0\Deploy-NetworkSecurityAgent.ps1" `
    -Destination "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\scripts\"
```

**c) Yangi GPO yaratish va bog'lash** (Group Policy Management Console orqali):

1. `gpmc.msc` oching
2. Kerakli OU (masalan "Corporate Computers") ustida o'ng tugma →
   **"Create a GPO in this domain, and Link it here"**
3. Nomi: masalan `Network Security Agent - Auto Deploy`
4. Yaratilgan GPO'ni tahrirlash (**Edit**):
   - **Computer Configuration** → **Policies** → **Windows Settings**
     → **Scripts (Startup/Shutdown)** → **Startup**
   - **"PowerShell Scripts"** tab'ida **"Add"** → skript yo'lini
     (`\\domain\SYSVOL\domain\scripts\Deploy-NetworkSecurityAgent.ps1`)
     ko'rsating
5. **"Enforced"** qilib belgilang (agar boshqa GPO'lar bilan
   to'qnashmasligi kerak bo'lsa)

**d) Kuchga kiritish**:

Kompyuterlar keyingi reboot'da (yoki `gpupdate /force` + reboot bilan
majburan) avtomatik agentni o'rnatadi. Bir nechta kompyuterda majburan
qo'llash uchun (test uchun foydali):

```powershell
Invoke-GPUpdate -Computer "PC-NAME" -Force
```

### 5.4. Bitta kompyuterda qo'lda test qilish (GPO'ga o'tishdan oldin tavsiya etiladi)

GPO orqali barcha kompyuterlarga tarqatishdan oldin, bitta test
kompyuterda `Install-NetworkSecurityAgent.ps1` orqali qo'lda sinab
ko'ring (Administrator PowerShell'da, arxiv ichidagi papkada turib):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
.\Install-NetworkSecurityAgent.ps1 -ApiServerUrl "http://172.16.0.5:8443" -ApiKey "sizning-kalitingiz"
```

Muvaffaqiyatli bo'lsa, `Get-Service NetworkSecurityEndpointAgent`
"Running" holatini ko'rsatishi va bir necha daqiqadan so'ng
Dashboard'ning `/asset-inventory` sahifasida shu kompyuter
`agent_last_heartbeat` bilan ko'rinishi kerak.

### 5.5. Qamrovni kuzatish (Agent Coverage Report)

GPO orqali tarqatish "hamma joyga yetdimi?" savolini avtomatik javob
berish uchun, tizimda **Agent Coverage Report** mavjud
(`network_discovery/agent_coverage.py`) - bu AD'dagi barcha
kompyuterlar ro'yxatini agent'dan kelayotgan "heartbeat" xabarlari
bilan solishtiradi:

```bash
python -m network_discovery.agent_coverage
```

Natija - `covered` (agent faol), `stale` (agent o'rnatilgan edi, lekin
24+ soat javob bermayapti - o'chirilgan/ishdan chiqqan bo'lishi
mumkin), `missing` (hali umuman o'rnatilmagan). Dashboard'da
`/agent-coverage` sahifasida (faqat admin) vizual ko'rinishda.

### 5.6. Test holati (halol tushuntirish)

| Qism | Holat |
|---|---|
| `NetworkSecurityAgent.exe` (PyInstaller build) | ✅ **HAQIQIY Windows'da** (GitHub Actions `windows-latest` runner) qurilgan va `--help` bilan ishga tushirilgani tasdiqlangan |
| `Deploy-NetworkSecurityAgent.ps1` / `Install-NetworkSecurityAgent.ps1` (o'zi) | ⚠️ Faqat qavslar/tirnoq balansi qo'lda tekshirilgan - to'liq ijro (xizmat sifatida o'rnatish, GPO orqali ishga tushish) sinalmagan, chunki bu Active Directory domeni va Group Policy infratuzilmasini talab qiladi |
| Agent Coverage Report (Python/LDAP qismi) | ✅ Haqiqiy OpenLDAP server bilan to'liq test qilingan |
| Agent Heartbeat (`/api/v1/agent_heartbeat`) | ✅ To'liq real HTTP orqali test qilingan |

**Tavsiya**: GPO'ga o'tishdan oldin, 5.4-bo'limdagi kabi kamida bitta
test kompyuterda qo'lda sinab ko'ring.

## 6. Xavfsizlik va cheklovlar (halol tushuntirish)

- **Offline holat**: agent internetdan uzilgan noutbukda ham ishlashi
  uchun mahalliy kesh (`agent_hash_cache.json`) ishlatadi. Lekin kesh
  bo'sh bo'lsa (masalan birinchi marta ko'rilgan fayl) va server bilan
  bog'lanib bo'lmasa, agent xavfsizlik siyosatiga ko'ra faylni **bloklamaydi**
  (false-positive bilan ish jarayonini to'xtatmaslik uchun) - bu ataylab
  qilingan qaror, lekin sizning xavfsizlik siyosatingizga qarab
  o'zgartirilishi mumkin (`check_hash_with_server_or_cache()` funksiyasida).
- **TLS-shifrlangan fayllar** (Telegram Desktop, brauzer orqali HTTPS):
  agent tarmoq darajasida emas, **fayl diskka yozilgandan keyin** ishlaydi -
  shuning uchun TLS Inspection kerak emas, chunki fayl baribir diskka
  tushishi kerak (bu aynan TZ'dagi "Endpoint Agent - eng tavsiya etiladi"
  yechimining afzalligi).
- **Administrator huquqi**: boshqa foydalanuvchi jarayonini to'xtatish
  uchun agent Windows Service sifatida (LocalSystem huquqi bilan)
  ishlashi kerak - oddiy foydalanuvchi huquqida ba'zi jarayonlarni
  to'xtata olmasligi mumkin.
