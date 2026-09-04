# Ruijie Cloud Discovery sozlash — `network_discovery/ruijie_discovery.py`

`network_discovery/unifi_discovery.py` bilan bir xil naqsh - Ruijie
Cloud (Reyee/RG seriyali switch/AP)ga ulangan klientlar ro'yxatini
avtomatik olib, Dashboard'ning `/asset-inventory`/`/devices`
sahifalariga yozadi.

## 1. Kerakli hisob ma'lumotlarini olish (o'z-o'zidan xizmat KO'RSATILMAYDI)

Ruijie Cloud Open API kredensiallari (App ID/App Secret/API Token)
Ruijie Cloud veb-konsolida o'zingiz yarata olmaysiz - bu **Ruijie'ning
o'z qo'llab-quvvatlash jamoasi orqali qo'lda ko'rib chiqiladigan**
so'rov (rasmiy Ruijie forumidagi ikkita alohida xodim javobi bilan
tasdiqlangan).

**Ikkita usul:**

1. **Email orqali**: `service_rj@ruijienetworks.com` manziliga quyidagi
   ma'lumotlar bilan xat yuboring:
   - Customer Name (kompaniya nomi)
   - Cloud Email (Ruijie Cloud hisobingiz email manzili)
   - Country
   - API Purpose (qisqacha: "network device/client discovery
     integration with internal security monitoring system")
   - User Role: **VAD** (Value-Added Distributor) / **SUB**
     (Subscriber) / **SI** (System Integrator) - oddiy tugash
     mijoz/integratsiya uchun odatda **SI**.

2. **RITA qo'llab-quvvatlash chati orqali**:
   https://networks.s5.udesk.cn/im_client/?web_plugin_id=1296&language=en-us
   - "Open API access" so'rab murojaat qiling.

Ruijie R&D jamoasi ko'rib chiqib, sizga **App ID** va **App Secret**ni
(ilova kredensiallari) va alohida **API Token**ni (bir martalik,
doimiy - `accessToken` olish uchun ishlatiladi) yuboradi. Bu jarayon
DARHOL emas - ko'rib chiqish vaqti talab qiladi.

## 2. `.env` sozlash

```
RUIJIE_BASE_URL=https://cloud-us.ruijienetworks.com   # yoki cloud-as./cloud-eu. (mintaqangizga qarab)
RUIJIE_APP_ID=<Ruijie'dan olingan App ID>
RUIJIE_APP_SECRET=<Ruijie'dan olingan App Secret>
RUIJIE_API_TOKEN=<Ruijie'dan olingan API Token>
RUIJIE_GROUP_ID=                                       # bo'sh qoldiring - avtomatik barcha loyihalar
RUIJIE_VERIFY_SSL=true
```

Qaysi mintaqaviy manzil (`cloud-us`/`cloud-as`/`cloud-eu`) ishlatilishi
kerakligini hisobingiz qaysi mintaqada ro'yxatdan o'tganiga qarab
Ruijie qo'llab-quvvatlash bilan tasdiqlab oling (aynan shu manzilga
kredensiallar bog'langan bo'ladi).

`RUIJIE_GROUP_ID` bo'sh qoldirilsa, hisobdagi BARCHA loyiha/filial
("BUILDING" turidagi guruh)lar avtomatik topilib, ularning barchasidan
klientlar yig'iladi - UniFi'dan farqli, bu yerda bitta "site ID"ni
qo'lda topish shart emas.

## 3. Ishlatish

```bash
# Faqat Ruijie'dan (ARP/ICMP'siz):
python -m network_discovery.asset_inventory --ruijie-only

# Yoki to'liq discovery aylanishining bir qismi sifatida
# (RUIJIE_APP_ID sozlangan bo'lsa avtomatik ishga tushadi):
python -m network_discovery.asset_inventory --cidr 172.16.0.0/22 --interface eth0
```

Natija `devices` jadvaliga `discovery_source="ruijie"` bilan yoziladi,
Dashboard'ning `/asset-inventory` va `/devices` sahifalarida ko'rinadi.

## 4. Real test holati (halol)

Bu integratsiya rasmiy Ruijie API hujjatiga emas, ochiq-manbali
`pyruijie` mijoz kutubxonasining (Apache 2.0, GitHub:
`dannielperez/pyruijie`) manba kodiga qarab yozilgan - u yerda
so'rov yo'llari/maydon nomlari aniq. **Haqiqiy `cloud.ruijienetworks.
com`ga qarshi live test hali qilinmagan** (hisob kredensiallari hali
mavjud emas - yuqoridagi 1-bo'limga qarang), lekin `run_full_test.py`
testi (#74) real HTTP protokoli, real JSON konvert (`{"code":0,...}`),
real autentifikatsiya oqimi va real sahifalab-olish (pagination)
mantig'ini soxta (mock) Flask server orqali to'liq tekshiradi - kod
o'zi real yoki soxta serverni farqlamaydi (server manzili
`RUIJIE_BASE_URL` orqali to'liq almashtiriladi).

**Kredensiallar olingandan keyin**: shu `.env` qatorlarini to'ldirib,
`python -m network_discovery.asset_inventory --ruijie-only` ni real
hisobga qarshi ishga tushiring - agar biror joyda nomuvofiqlik
topilsa (masalan `connectType`ning boshqa qiymati, yoki guruh
daraxtining kutilmagan shakli), `network_discovery/ruijie_discovery.py`
mos ravishda yangilanishi kerak bo'ladi.
