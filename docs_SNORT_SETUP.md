# Snort — Suricata'ga alternativ IDS (yangi TZ 8-bo'lim)

## Snort vs Suricata — qachon qaysi birini tanlash

| | Suricata | Snort |
|---|---|---|
| Fayl ekstraktsiyasi (`file-store`) | ✅ Bor | ❌ Yo'q (alohida vosita kerak) |
| Ko'p yadroli (multi-threading) | ✅ Zamonaviy | Snort 3 da bor, Snort 2'da yo'q |
| JSON chiqish (`eve.json`) | ✅ | Snort 3'da bor, Snort 2'da faqat matn/unified2 |
| Qoidalar formati | Suricata/Snort qoidalari (ko'pi bir xil) | Snort qoidalari (VRT/ET) |
| Loyihadagi holat | **Asosiy IDS** (4-bosqich, file-store orqali) | **Qo'shimcha/zaxira IDS** (faqat alert-based) |

**Xulosa**: bu loyihada Suricata **asosiy** IDS bo'lib qoladi (fayl
ekstraktsiyasi kerak bo'lgani uchun). Snort **qo'shimcha qatlam**
sifatida qo'shiladi — masalan alohida segmentda, yoki Suricata bilan
parallel, turli qoidalar to'plamlari bilan ishlash uchun.

## O'rnatish

```bash
sudo apt install snort
```

O'rnatish jarayonida interfeys va HOME_NET so'raladi - buni keyin
`/etc/snort/snort.conf`da o'zgartirish mumkin.

## Sozlash

`/etc/snort/snort.conf`:
```
var HOME_NET 172.16.0.0/22
var EXTERNAL_NET !$HOME_NET

# Qoidalar fayllari
include /etc/snort/rules/local.rules
```

`/etc/snort/rules/local.rules` (namuna qoidalar):
```
alert tcp any any -> $HOME_NET 4444 (msg:"Suspicious C2 port 4444"; sid:1000001; rev:1; priority:1;)
alert tcp any any -> $HOME_NET 3389 (msg:"RDP access attempt"; sid:1000002; rev:1; priority:2;)
alert tcp $HOME_NET any -> any 6667 (msg:"IRC traffic (potential botnet C2)"; sid:1000003; rev:1; priority:1;)
```

Rasmiy qoidalar to'plamlarini ulash uchun (Emerging Threats, bepul):
```bash
sudo oinkmaster -o /etc/snort/rules
```

## Ishga tushirish (SPAN port orqali, IDS rejimida)

```bash
sudo snort -c /etc/snort/snort.conf -i eth1 -A fast -l /var/log/snort/ -D
```

- `-i eth1` — SPAN portga ulangan interfeys (docs_SURICATA_SETUP.md'dagi
  SPAN sozlash bosqichi bilan bir xil)
- `-A fast` — tezkor, bir qatorli alert formati (bizning parser shu
  formatni kutadi)
- `-D` — daemon rejimida (fon jarayoni)

## Bizning tizim bilan integratsiya

`collectors/snort_reader.py` `/var/log/snort/alert` faylini kuzatib,
har bir alert qatorini `Event` + `Alert` sifatida bazaga yozadi
(Suricata'dan farqli, oraliq hash-tekshiruv bosqichisiz - Snort
alert'ining o'zi allaqachon "yakuniy signal").

```bash
python -m collectors.snort_reader --file /var/log/snort/alert
```

Priority -> severity moslashuvi:
| Snort Priority | Bizning severity |
|---|---|
| 1 | critical |
| 2 | high |
| 3 | medium |
| 4+ | low |

## Test qilingan format (haqiqiy Snort chiqishi)

Bu loyihada Snort **pcap fayl orqali** (`snort -r fayl.pcap`) haqiqiy
ishga tushirilib, chiqish formati tasdiqlangan (jonli tarmoq capture
sandbox muhitida ishlamagani uchun - `docs_SURICATA_SETUP.md`da ham
shu cheklov bor). Haqiqiy Snort natijasi:

```
08/06-08:39:01.972343  [**] [1:1000001:1] TEST Suspicious port 4444 (C2-like) [**] [Priority: 1] {TCP} 10.0.0.5:51234 -> 10.0.0.99:4444
```

`collectors/snort_reader.py`ning regex'i aynan shu formatga mos
yozilgan va test qilingan.
