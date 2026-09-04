# Kerio Control - syslog forwarding sozlash

Bu tizim Kerio Control'ni **FAQAT** ikkita maqsad uchun ishlatadi
(arxitektura qarori - `CLAUDE.md`ga qarang):

1. **Host log** - IP/MAC/hostname bog'lanishi (DHCP orqali kim qaysi
   IP'ni olgani) - `devices` jadvalini to'ldiradi.
2. **Connection log** - qaysi ichki qurilma qaysi tashqi manzilga
   ulangani - `events` jadvalini to'ldiradi, bu esa Dashboard'ning
   **Live Network Map** (`/live-map`) sahifasi uchun ASOSIY manba.

Xavfni aniqlash (threat detection) Kerio orqali EMAS - bu Suricata
zimmasida (`docs_SURICATA_SETUP.md`).

## MUHIM (real production'da aniqlangan xato, tuzatilgan)

Loyihaning avvalgi versiyasidagi parser (`parsers/kerio_parser.py`)
Kerio Control'ning **haqiqiy** log formatiga emas, balki umumiy
taxminiy formatga (`SRC=... DST=... DPT=...`, `DHCP: Lease granted...`)
qarab yozilgan edi - bu format Kerio Control'da **umuman mavjud emas**.
Rasmiy Kerio hujjatlari orqali tasdiqlangan **haqiqiy** formatlar:

```
Connection log:
[18/Apr/2013 10:22:47] [ID] 613181 [Rule] NAT [Service] HTTP [User] winston
[Connection] TCP 192.168.1.140:1193 > hit.google.com:80 [Duration] 121 sec
[Bytes] 1575/1290/2865 [Packets] 5/9/14

Host log:
[04/Mar/2014 12:07:28] [IPv4] 10.10.30.81 [MAC] 00-0c-29-1d-cc-bd
(Apple) [Hostname] jsmith-cp
```

Parser endi shu HAQIQIY formatlarni o'qiydi (real, hujjatlashtirilgan
namunalar bilan sinovdan o'tkazilgan - `run_full_test.py`).

## 0-qadam (MUHIM, ko'pincha unutiladi): Connection loggingni Traffic Rules'da yoqish

**Real production'da aniqlangan holat**: syslog forwarding to'g'ri
sozlangan bo'lsa ham, agar Kerio Control'ning o'zi **"Connection"** log
sahifasida "Данные отсутствуют" / "No data" ko'rsatsa - muammo syslog'da
EMAS, Kerio hech qanday ulanishni umuman qayd etmayapti. Kerio
Control'da trafik oqimi avtomatik loglanmaydi - buni har bir **Traffic
Rule** (trafik qoidasi) uchun ALOHIDA yoqish kerak:

1. **Configuration → Traffic Rules** (yoki eski versiyalarda
   **Traffic Policy**) bo'limiga o'ting.
2. Qaysi qoidalar bo'yicha o'tayotgan trafikni ko'rmoqchi bo'lsangiz
   (odatda asosiy "Internet access" qoidasi), o'sha qatorning **"Log"**
   ustunidagi katakchani (yoki qoidani ochib, **"Log matched
   connections"** belgisini) yoqing.
3. O'zgarishlarni saqlang (**Apply**).

Shundan keyin **Connection** log sahifasida (Kerio'ning o'z
interfeysida) yozuvlar ko'rina boshlashi kerak - agar hali ham bo'sh
bo'lsa, syslog sozlashga o'tishdan oldin shuni tekshiring (ulanish
tugagandan/uzilgandan KEYIN yoziladi - uzoq davom etadigan ulanishlar
darhol ko'rinmasligi mumkin).

## Sozlash qadamlari (Kerio Control Administration) - syslog forwarding

Kerio Control'da syslog **har bir log turi uchun ALOHIDA** yoqiladi
(bitta umumiy "syslog yoqish" tugmasi yo'q). Ekranning chap tomonidagi
log ro'yxatida (Alert/Config/Connection/Debug/Dial/Error/Filter/
Host/Http/Security/Warning/Web) kerakli logni tanlang:

1. **Status → Logs** (yoki chap paneldagi "hujjat" belgisi) bo'limiga
   o'ting.
2. **Connection** log'ni tanlang.
3. Log ichida istalgan joyga o'ng tugma bosing → **Log Settings**.
4. **External Logging** tab'ida **"Enable Syslog logging"**ni belgilang.
5. **Syslog Server** maydoniga bu serverning manzilini kiriting:
   `<server-IP>:514` (masalan `172.16.1.206:514` - standart syslog
   porti, agent_api/dashboard portlari bilan aralashtirmang).
6. Xuddi shu amalni **Host** log uchun ham takrorlang (2-5 qadamlar) -
   bu allaqachon sizda ishlab turibdi (real testda tasdiqlangan).

**Boshqa log turlarini (Debug, Filter, Security va h.k.) yoqish shart
emas** - parser ularni tanimaydi, faqat keraksiz trafik yaratadi.

## Tekshirish

Sozlashdan keyin, serverda:

```bash
docker logs -f network_security_system-syslog_collector-1
```

Bir necha daqiqa ichida `[Connection]` va `[IPv4]...[MAC]...[Hostname]`
qatorlari ko'rinishi kerak. Keyin:

```bash
docker exec network_security_system-postgres-1 psql -U security__admin \
  -d security_system_admin -c "SELECT COUNT(*) FROM events WHERE timestamp > now() - interval '1 hour';"
```

Agar son o'sib borsa - Live Map (`/live-map`) sahifasida real
qurilmalar/aloqalar ko'rina boshlaydi (avtomatik, 15 soniyada
yangilanadi).

## Halol cheklov

Bu qo'llanma **rasmiy Kerio Control hujjatlariga** asoslangan (menyu
nomlari/joylashuvi versiyalar orasida biroz farq qilishi mumkin - agar
"Log Settings" yoki "External Logging" nomlari sizning versiyangizda
boshqacha bo'lsa, Kerio Control'ning o'z "Help" tugmasiga qarang).
Haqiqiy Kerio Control administratsiya paneliga kirish imkoni bu
loyihada YO'Q edi - shuning uchun ekran skrinshotlari bilan emas,
matn ko'rsatmalari bilan cheklangan.
