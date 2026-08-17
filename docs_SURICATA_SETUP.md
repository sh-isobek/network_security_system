# Suricata (IDS/IPS) sozlash — 2-3-bosqich

## 1. Nega SPAN (Mirror) port kerak

Suricata tarmoq trafigini "eshitish" uchun switch/router'dan **nusxa** oladi.
Bu haqiqiy trafikka aralashmaydi (faqat kuzatish — IDS rejimi) yoki
in-line qo'yilib bloklashi ham mumkin (IPS rejimi, TAP yoki bridge kerak).

**Boshlang'ich bosqichda IDS rejimi tavsiya etiladi** (faqat kuzatish,
bloklash alohida firewall/gateway orqali amalga oshiriladi — TZ'dagi
qarorga mos).

### Switch tomonida (namuna, Cisco-uslub buyruqlar; Ruijie/Aruba o'xshash mantiqqa ega)

```
monitor session 1 source interface Gi0/1 - Gi0/24
monitor session 1 destination interface Gi0/25
```

`Gi0/25` portiga Suricata ishlaydigan serverning tarmoq kartasi ulanadi.
Bu interfeys **IP manzilsiz, promiscuous rejimda** ishlaydi (faqat tinglaydi).

### UniFi Controller orqali (sizning holatingiz - Switch + UDM)

Sizda alohida **UniFi Switch** va **UDM** bor - eng to'liq qamrov
uchun Switch'ning **UDM'ga ketuvchi uplink porti**ni oyna (mirror)
sifatida sozlaymiz (bu orqali ichki va tashqi barcha trafik ko'rinadi).

1. **UniFi Network Controller**ga kiring (`https://172.16.0.64:11443`)
2. **Devices** → sizning **Switch**ingizni tanlang (UDM emas, Switch)
3. **Ports** bo'limiga o'ting
4. Serveringiz ulanadigan (yoki ulanishi kerak bo'lgan) **bo'sh portni**
   tanlang → **Edit**
5. **"Operation"** bo'limida → **"Mirroring"**ni tanlang
6. **"Mirroring Port"** maydonida → Switch'ning **UDM'ga ulangan
   uplink porti**ni ko'rsating (bu barcha ichki+tashqi trafikni
   ko'rish imkonini beradi)
7. **Apply**ni bosing

**MUHIM (jismoniy talab)**: Suricata ishlaydigan serveringizda
(`172.16.1.206`) buning uchun **ikkinchi, alohida tarmoq kartasi**
kerak bo'ladi:
- Birinchi karta (`eth0`, `172.16.1.206`) - odatdagidek, SSH/Docker
  uchun IP bilan ishlaydi
- Ikkinchi karta (masalan `eth1`) - **IP manzilsiz**, yuqoridagi
  6-bosqichda tanlangan mirror portiga jismoniy kabel bilan ulanadi,
  faqat "tinglash" (promiscuous) rejimida ishlaydi

Agar serveringizda hozircha faqat bitta tarmoq kartasi bo'lsa, yangi
PCIe/USB tarmoq kartasi qo'shish kerak bo'ladi (bu - standart, arzon
apparat talabi, Suricata/SPAN sozlashning ajralmas qismi).

**Eslatma**: ba'zi UniFi Switch modellari **bir vaqtning o'zida faqat
bitta manba portini** oynalashni qo'llab-quvvatlaydi (ko'p-manbali
mirroring cheklangan bo'lishi mumkin) - agar sizga bir nechta VLAN/
portni birlashtirib kuzatish kerak bo'lsa, switch modelingiz hujjatini
tekshiring yoki `community.ui.com`da qidiring.

## 2. Suricata o'rnatish (Ubuntu/Debian asosidagi server)

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata -y
```

## 3. Asosiy sozlash — `/etc/suricata/suricata.yaml`

### a) Tinglash interfeysi

```yaml
af-packet:
  - interface: eth1        # SPAN portga ulangan interfeys
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

### b) Fayl ekstraktsiyasini yoqish (file-store)

Bu — loyihaning eng muhim qismi: Suricata tarmoqdan o'tayotgan
EXE/DLL/MSI/ZIP/RAR/DOCM/JS/PDF va h.k. fayllarni diskka saqlaydi va
ularning SHA256/MD5 hash'ini `eve.json` ichiga yozadi.

```yaml
file-store:
  version: 2
  enabled: yes
  dir: /var/log/suricata/files
  write-fileinfo: yes
  stream-depth: 0          # cheklovsiz - katta fayllarni ham to'liq oladi

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - fileinfo:
            force-magic: yes
            force-hash: [sha256, md5]
        - alert:
            payload: yes
        - flow:
        - dns:
```

### c) Qaysi fayl turlarini kuzatish (`file-store` uchun qoida)

`/etc/suricata/rules/file-extraction.rules` fayli yarating:

```
alert http any any -> any any (msg:"EXE fayl yuklandi"; filestore; filemagic:"PE32"; sid:1000001;)
alert http any any -> any any (msg:"MSI fayl yuklandi"; filestore; fileext:"msi"; sid:1000002;)
alert http any any -> any any (msg:"ZIP arxiv yuklandi"; filestore; fileext:"zip"; sid:1000003;)
alert http any any -> any any (msg:"RAR arxiv yuklandi"; filestore; fileext:"rar"; sid:1000004;)
alert http any any -> any any (msg:"DOCM fayl yuklandi"; filestore; fileext:"docm"; sid:1000005;)
alert http any any -> any any (msg:"XLSM fayl yuklandi"; filestore; fileext:"xlsm"; sid:1000006;)
alert http any any -> any any (msg:"JS skript yuklandi"; filestore; fileext:"js"; sid:1000007;)
alert http any any -> any any (msg:"VBS skript yuklandi"; filestore; fileext:"vbs"; sid:1000008;)
alert http any any -> any any (msg:"PDF fayl yuklandi"; filestore; fileext:"pdf"; sid:1000009;)
alert http any any -> any any (msg:"ISO fayl yuklandi"; filestore; fileext:"iso"; sid:1000010;)
alert http any any -> any any (msg:"APK fayl yuklandi"; filestore; fileext:"apk"; sid:1000011;)
alert http any any -> any any (msg:"DLL fayl yuklandi"; filestore; filemagic:"PE32"; sid:1000012;)
```

`suricata.yaml`da bu faylni ulang:
```yaml
rule-files:
  - file-extraction.rules
```

## 4. Ishga tushirish

```bash
sudo suricata -c /etc/suricata/suricata.yaml --af-packet -D
```

`/var/log/suricata/eve.json` fayli paydo bo'ladi — har bir aniqlangan
fayl uchun `"event_type":"fileinfo"` yozuvi, ichida `sha256`, `filename`,
`magic`, `size`, `src_ip`, `dest_ip` maydonlari bilan.

## 5. Bizning tizim bilan integratsiya

Python tomonda `collectors/suricata_reader.py` `eve.json` faylini
doimiy o'qib turadi (`tail -f` uslubida), faqat `fileinfo` event'larni
oladi va bazamizdagi `file_events` jadvaliga yozadi. Undan keyin
`engine/file_analysis_engine.py` hash'larni tekshiradi.

### Docker orqali ishga tushirish

`docker-compose.yml`da `suricata_reader` xizmati allaqachon sozlangan -
u host'dagi `/var/log/suricata/eve.json`ni konteynerga faqat-o'qish
(`:ro`) rejimida bog'laydi.

**MUHIM (Docker'ning tanilgan nozik nuqtasi)**: agar `eve.json` fayli
Suricata tomonidan hali yaratilmagan bo'lsa, Docker uni **bo'sh papka**
sifatida avtomatik yaratib qo'yishi mumkin (fayl o'rniga) - bu keyinroq
haqiqiy Suricata faylni yoza olmay qolishiga olib keladi. Shuning
uchun **Suricata o'rnatishdan oldin ham, keyin ham**, `docker compose
up`dan oldin quyidagini bajaring:

```bash
sudo mkdir -p /var/log/suricata
sudo touch /var/log/suricata/eve.json
docker compose up -d suricata_reader
```

Tekshirish:
```bash
docker compose logs suricata_reader --tail 20
```
Suricata haqiqiy fayl aniqlasa, "Fayl aniqlandi: ..." kabi xabarlar
ko'rinishi kerak.

### Real fayl bilan qo'lda sinash (Suricata'siz ham)

Suricata to'liq sozlanmasdan oldin ham, zanjirning Python qismini
sinab ko'rish mumkin - haqiqiy formatdagi `eve.json` qatori bilan:
```bash
docker compose exec dashboard python -m collectors.suricata_reader --file /path/to/test_eve.json --once
docker compose exec dashboard python -m engine.file_analysis_engine
```

## Muhim cheklov (HTTPS haqida, siz to'g'ri ta'kidlagansiz)

Yuqoridagi qoidalar **faqat HTTP** (shifrlanmagan) trafikda ishlaydi.
Telegram, Gmail, OneDrive kabi HTTPS orqali kelayotgan fayllarni Suricata
ko'ra olmaydi — buning uchun TLS Inspection yoki Endpoint Agent kerak
(8 va 6-bosqichlarda ko'rib chiqiladi).

## ClamAV integratsiyasi (antivirus qatlami)

YARA'ga qo'shimcha ravishda, deep-scan bosqichida `clamscan` orqali
sanoat standarti antivirus signaturalari bilan ham tekshiriladi.

O'rnatish:
```bash
sudo apt install clamav clamav-freshclam
```

**MUHIM: virus bazasini muntazam yangilab turish shart**, aks holda
yangi tahdidlar aniqlanmaydi:
```bash
# /etc/cron.d/freshclam (odatda paket o'rnatilganda avtomatik yaratiladi)
0 */2 * * * root freshclam --quiet
```

Bazani qo'lda birinchi marta yuklash:
```bash
sudo freshclam
```

Agar server tashqi internetga cheklangan (masalan faqat ichki tarmoq)
bo'lsa, `freshclam`ning `DatabaseMirror` sozlamasini ichki oynali proxy
yoki mahalliy oyna serveriga yo'naltirish kerak bo'ladi
(`/etc/clamav/freshclam.conf`).

**.env sozlamasi:**
```
CLAMAV_DB_DIR=/var/lib/clamav
```
