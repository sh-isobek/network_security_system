# Zeek — tarmoq tahlil freymvorki (yangi TZ 8-bo'lim)

## Zeek nima va nega kerak

Zeek klassik "signature-based" IDS emas (Suricata/Snort'dan farqli) -
u tarmoqdagi **har bir aloqa haqida boy metadata** yozadi (`conn.log`,
`dns.log`, `http.log`, `ssl.log`, `files.log`) va shubhali xatti-harakat
haqida o'z tekshiruvlari (`notice.log`) orqali xabar beradi. Bu
retrospektiv tekshiruv ("bu IP oxirgi 30 kunda kimlar bilan gaplashgan?")
va anomaliya tahlili uchun ayniqsa foydali.

## MUHIM: o'rnatish cheklovi

Zeek rasmiy ravishda faqat quyidagilar orqali tarqatiladi:
- **OpenSUSE Build Service** (`download.opensuse.org`)
- **Docker Hub** (`docker pull zeek/zeek`)
- Manba koddan build qilish (`git clone --recursive` + kompilyatsiya,
  juda ko'p vaqt va resurs talab qiladi)

Standart Ubuntu/Debian `apt` repolarida **yo'q**. Agar tashkilotingiz
tarmog'i shu domenlarga kirish imkonini bersa, quyidagi yo'riqnoma
ishlaydi. Agar yo'q bo'lsa - Docker orqali o'rnatish eng oson yo'l.

## O'rnatish (Docker orqali, tavsiya etiladi)

```bash
docker pull zeek/zeek:lts
docker run -d --name zeek --net=host \
    -v /var/log/zeek:/opt/zeek/logs/current \
    zeek/zeek:lts zeek -i eth1 local
```

`--net=host` va `-i eth1` — SPAN portga ulangan interfeys
(`docs_SURICATA_SETUP.md`dagi SPAN sozlash bosqichi bilan bir xil).

## O'rnatish (paket orqali, agar OBS'ga kirish bo'lsa)

```bash
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' | \
    sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | \
    sudo gpg --dearmor -o /etc/apt/trusted.gpg.d/security_zeek.gpg
sudo apt update
sudo apt install zeek-lts
```

## Sozlash — JSON log formatini yoqish

**MUHIM**: standart holatda Zeek loglarni TSV (tab-separated) formatida
yozadi, bizning `collectors/zeek_reader.py` esa JSON Lines kutadi.
`/opt/zeek/share/zeek/site/local.zeek` fayliga qo'shing:

```
@load policy/tuning/json-logs.zeek
```

Yoki eskiroq versiyalarda:
```
redef LogAscii::use_json = T;
```

## Bizning tizim bilan integratsiya

```bash
python -m collectors.zeek_reader --log-dir /opt/zeek/logs/current --once
```

`--once` — mavjud loglarni bir marta o'qiydi (cron orqali har necha
daqiqada ishga tushirish mumkin). Qo'llab-quvvatlanadigan fayllar:

| Zeek log | Bizning tizimda | Izoh |
|---|---|---|
| `notice.log` | `Alert` | Zeek'ning o'z ichki alerting mexanizmi |
| `dns.log` | `Event` + blacklist tekshiruvi | Mavjud whitelist/blacklist bilan bir xil mantiq |
| `conn.log` | `Event` | Oddiy tarmoq aloqasi |
| `files.log` | `FileEvent` | **Suricata bilan bir xil jadval** - `sha256` allaqachon bor, `file_analysis_engine`/`deep_scan_engine` avtomatik oladi, alohida kod kerak emas |

## Test holati (halol tushuntirish)

Zeek binary'sining o'zi bu loyiha tayyorlangan sandbox muhitida
o'rnatib bo'lmagani uchun (yuqoridagi domen cheklovi), integratsiya
**haqiqiy Zeek chiqishi bilan sinalmagan**. Buning o'rniga:
- Kod Zeek'ning rasmiy hujjatlashtirilgan JSON sxemasiga
  (https://docs.zeek.org) qat'iy mos yozilgan.
- Sxemaga aniq mos sintetik ma'lumot bilan to'liq test qilingan -
  jumladan `files.log` orqali kelgan fayl mavjud
  `file_analysis_engine`ga avtomatik o'tib, to'g'ri "malicious" deb
  belgilanishi va Alert yaratilishi tasdiqlangan.
- Birinchi marta haqiqiy Zeek bilan ishga tushirilganda, log
  fayllarining aniq maydon nomlarini (`ts`, `id.orig_h` va h.k.)
  o'zingizning Zeek versiyangiz chiqishi bilan solishtirib
  tekshirishni tavsiya qilaman - versiyalar orasida kichik farqlar
  bo'lishi mumkin.
