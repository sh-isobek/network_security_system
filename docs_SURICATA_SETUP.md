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

Python tomonda `collectors/suricata_reader.py` (keyingi qadamda yoziladi)
`eve.json` faylini doimiy o'qib turadi (`tail -f` uslubida), faqat
`fileinfo` event'larni oladi va bazamizdagi `file_events` jadvaliga yozadi.
Undan keyin `engine/file_analysis_engine.py` hash'larni tekshiradi.

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
