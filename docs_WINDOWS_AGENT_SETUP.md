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

## 5. Xavfsizlik va cheklovlar (halol tushuntirish)

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
