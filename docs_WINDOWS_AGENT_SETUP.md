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

```powershell
setx API_SERVER_URL "https://172.16.0.5:8443"
setx AGENT_API_KEY "<markazdagi bilan bir xil kalit>"
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

### 5.1. Qanday ishlaydi

```
[Domain Controller]                    [Har bir Windows PC]
  SYSVOL\...\scripts\
    NetworkSecurityAgent\
      windows_agent/ (fayllar)    ──►   Kompyuter yoqiladi
      VERSION                            │
      api_key.secret                     ▼
                                    GPO Startup Script ishga tushadi
                                    (SYSTEM huquqi bilan, login'dan oldin)
                                          │
                                    Versiya solishtiradi:
                                    o'rnatilgan == mavjud?
                                      │           │
                                     HA           YO'Q
                                      │           │
                                  Chiqadi    Fayllarni nusxalaydi,
                                  (jim)      xizmatni o'rnatadi/
                                             qayta ishga tushiradi
```

### 5.2. Sozlash qadamlari

**a) SYSVOL'da agent paketini tayyorlash** (Domain Controller'da):

```powershell
$SysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN\scripts\NetworkSecurityAgent"
New-Item -ItemType Directory -Path $SysvolPath -Force

# Loyihaning windows_agent/, agent_core/, config/ papkalarini nusxalang
Copy-Item -Path "C:\Path\To\Repo\windows_agent" -Destination $SysvolPath -Recurse
Copy-Item -Path "C:\Path\To\Repo\agent_core" -Destination $SysvolPath -Recurse
Copy-Item -Path "C:\Path\To\Repo\config" -Destination $SysvolPath -Recurse

# Versiya belgisi (har yangilanishda oshiring)
Set-Content -Path "$SysvolPath\VERSION" -Value "1.0.0"

# API kalitini alohida faylga (bu fayl uchun ACL orqali faqat
# "Domain Computers" guruhiga O'QISH huquqini bering, boshqa hech kimga)
Set-Content -Path "$SysvolPath\api_key.secret" -Value "<markazdagi AGENT_API_KEY bilan bir xil>"
```

**b) Deploy skriptini SYSVOL'ga qo'yish**:

```powershell
Copy-Item -Path "C:\Path\To\Repo\deploy\windows_agent_gpo\Deploy-NetworkSecurityAgent.ps1" `
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

### 5.3. Qamrovni kuzatish (Agent Coverage Report)

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

**MUHIM (halol tushuntirish)**: `Deploy-NetworkSecurityAgent.ps1`
skripti Windows/PowerShell/Active Directory infratuzilmasini talab
qiladi - bu loyiha tayyorlangan Linux sandbox muhitida ijro etib
sinalmagan (Zeek/Grafana bilan bir xil holat). Kod PowerShell
sintaksisi va GPO konventsiyalariga ehtiyotkorlik bilan mos yozilgan
(qavslar/tirnoq balansi qo'lda tekshirilgan), lekin **production'ga
qo'yishdan oldin bitta test kompyuterda albatta qo'lda sinab
ko'ring**. Agent Coverage Report (Python/LDAP qismi) esa haqiqiy
OpenLDAP server bilan to'liq test qilingan.

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
