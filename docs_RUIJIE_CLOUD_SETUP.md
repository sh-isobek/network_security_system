# Ruijie Cloud Discovery sozlash — `network_discovery/ruijie_discovery.py`

`network_discovery/unifi_discovery.py` bilan bir xil naqsh - Ruijie
Cloud (Reyee/RG-CBS seriyali switch/AP)ga ulangan klientlar ro'yxatini
avtomatik olib, Dashboard'ning `/asset-inventory`/`/devices`
sahifalariga yozadi.

## 1. Kerakli hisob ma'lumotlari

Ruijie Cloud'ning **"Open Platform / Ilova boshqaruvi"** bo'limida
yaratiladigan ikkita qiymat kifoya:

- **App Key** (`RUIJIE_APP_ID`)
- **App Secret** (`RUIJIE_APP_SECRET`)

**MUHIM (real test bilan tasdiqlangan)**: avtorizatsiya so'rovida
`token` degan nomdagi UCHINCHI so'rov parametri ham bor - lekin bu
mijozga xos maxfiy kalit EMAS, balki barcha mijozlar uchun BIR XIL,
qat'iy (o'zgarmas) qiymat. Kod ichida standart qiymat sifatida allaqachon
saqlangan (`network_discovery/ruijie_discovery.py`dagi `DEFAULT_
STATIC_TOKEN`) - alohida so'rab olish/sozlash SHART EMAS.

## 2. `.env` sozlash

```
RUIJIE_APP_ID=<Ruijie Cloud'dan olingan App Key>
RUIJIE_APP_SECRET=<Ruijie Cloud'dan olingan App Secret>
RUIJIE_BASE_URL=https://cloud.ruijienetworks.com   # standart qiymat, o'zgartirish shart emas
RUIJIE_POLL_INTERVAL=300                             # sekundlarda, ruijie_sync xizmati uchun
```

**MUHIM (real test bilan tasdiqlangan, ilgari noto'g'ri hujjatlashtirilgan
edi)**: to'g'ri baza manzil `https://cloud.ruijienetworks.com`
(mintaqaviy suffikssiz) - `cloud-us.ruijienetworks.com`/`cloud-as.
ruijienetworks.com` (ba'zi ochiq-manba mijoz kutubxonalarining standart
qiymati) haqiqiy hisobga qarshi `{"code":1,"msg":"Login failed"}`
qaytardi.

## 3. Ishlatish

```bash
# Faqat Ruijie'dan (ARP/ICMP'siz):
python -m network_discovery.asset_inventory --ruijie-only

# Yoki to'liq discovery aylanishining bir qismi sifatida
# (RUIJIE_APP_ID sozlangan bo'lsa avtomatik ishga tushadi):
python -m network_discovery.asset_inventory --cidr 172.16.0.0/22 --interface eth0

# Yoki davriy fon xizmati sifatida (docker-compose'da RUIJIE_APP_ID
# sozlangan bo'lsa `ruijie_sync` xizmati avtomatik shuni bajaradi):
python -m network_discovery.ruijie_sync_loop --loop --interval 300
```

Natija `devices` jadvaliga `discovery_source="ruijie"` bilan yoziladi,
Dashboard'ning `/asset-inventory` va `/devices` sahifalarida ko'rinadi.
Ishlab chiqaruvchi (`manufacturer`) maydoni Ruijie'ning o'zidan
to'g'ridan-to'g'ri keladi - mahalliy OUI bazasidan qayta qidirish
shart emas.

## 4. Real test holati (halol)

Bu integratsiya **HAQIQIY Ruijie Cloud hisobiga qarshi (foydalanuvchining
real App Key/App Secret'i bilan) qo'lda tasdiqlangan**: avtorizatsiya,
guruhlar (filiallar) daraxti, qurilmalar (switch/AP) va **235+ ta real
ulangan klient** (IP/MAC/ishlab chiqaruvchi bilan) muvaffaqiyatli
olindi va production bazaga yozildi. `run_full_test.py`dagi tegishli
test esa CI/offline muhitda takrorlanadigan bo'lishi uchun soxta
(mock) Flask server orqali xuddi shu zanjirni tekshiradi.

## 5. Halol cheklov: bloklash/kick hali yo'q

Ruijie Cloud veb-interfeysida "MAC bloklash" funksiyasi borligi
ma'lum (community forum muhokamalari orqali), lekin buning ochiq,
rasmiy hujjatlashtirilgan API endpoint'i topilmadi. Taxminiy/
tasdiqlanmagan endpoint bilan yozish xavfsiz emas - noto'g'ri so'rov
real ishlayotgan qurilmani kutilmaganda tarmoqdan uzib qo'yishi
mumkin. Buni qo'shish uchun: Ruijie Cloud veb-interfeysida "bloklash"
amalini brauzer DevTools (F12 → Network) orqali ushlab, aniq
endpoint/payload formatini olish kerak.
