# Network Discovery (yangi TZ 5-bo'lim)

## Umumiy ko'rinish

`network_discovery/` paketi tarmoqdagi barcha qurilmalarni avtomatik
aniqlaydi va `devices`/`topology_links` jadvallariga yozadi -
`/asset-inventory` sahifasida ko'rish mumkin.

| Modul | Vazifasi | Test holati |
|---|---|---|
| `icmp_scanner.py` | ICMP Ping Sweep (`nmap -sn`) | ✅ Real tarmoqda |
| `arp_scanner.py` | ARP Scan (`arp-scan`) | ✅ Real tarmoqda |
| `tcp_scanner.py` | TCP Port Scan + OS Fingerprint (`nmap -sT/-sV/-O`) | ✅ Real xizmatlar ustida |
| `udp_scanner.py` | UDP Scan (`nmap -sU`) | ✅ |
| `snmp_discovery.py` | SNMP Discovery (switch/printer/UPS) | ✅ Real SNMP agent bilan |
| `mac_vendor.py` | MAC Vendor (IEEE OUI, 32 500+ yozuv) | ✅ Real IEEE baza bilan |
| `dhcp_reader.py` | DHCP Lease o'qish (ISC dhcpd + Kerio) | ✅ |
| `kerio_discovery.py` | Kerio DHCP orqali discovery | ✅ |
| `ad_discovery.py` | Active Directory kompyuterlar | ✅ Real OpenLDAP bilan |
| `unifi_discovery.py` | UniFi Controller klientlari | ✅ Graceful fail (real controller yo'q) |
| `lldp_mapper.py` | LLDP topologiya | ✅ Real send+capture+parse |
| `cdp_mapper.py` | CDP (Cisco) topologiya | ✅ Real send+capture+parse |
| `asset_inventory.py` | Barchasini birlashtiruvchi, DB'ga yozuvchi | ✅ |
| `topology_builder.py` | LLDP/CDP'dan topologiya yig'uvchi | ✅ |
| `ipv6_discovery.py` | IPv6 (ICMPv6 ping sweep + NDP) | ⚠️ Kod to'g'ri, lekin sandbox kernelida IPv6 umuman yo'q - sinalmagan |
| `k8s_discovery.py` | Kubernetes Node Discovery | ✅ Real k3s klasterida (OS image, kubelet versiyasi bilan) |
| `virtualization_discovery.py` | VMware ESXi + Hyper-V | ✅ Graceful-fail (real ESXi/Hyper-V yo'q) |
| `cloud_discovery.py` | AWS/Azure/GCP asset discovery | ✅ Graceful-fail (real cloud credentials yo'q) |
| `wlc_discovery.py` | Cisco WLC/Aruba/Ruijie (SNMP-asosli, vendor-neytral) | ✅ Graceful-fail (real controller yo'q) |
| `scheduler.py` | Rejalashtirilgan + Differensial scan, Asset History | ✅ Real tarmoqda (discovered/disappeared/reappeared, dedup) |

## Yangi TZ 5-bo'lim: qo'shimcha talablar bo'yicha holat

| Talab | Holat |
|---|---|
| IPv6 Discovery | ⚠️ Kod tayyor, sandbox'da sinab bo'lmadi |
| VMware/Hyper-V host discovery | ✅ Kod tayyor, graceful-fail test qilingan |
| Kubernetes node discovery | ✅ **Real k3s klasterida test qilingan** |
| Cloud (AWS/Azure/GCP) discovery | ✅ Kod tayyor, graceful-fail test qilingan |
| Cisco WLC/Aruba/Ruijie | ✅ Vendor-neytral SNMP asos + REST API namunalari |
| OT/IoT chuqur fingerprint | ⚠️ `tcp_scanner.py`ning `-sV`/`-O` imkoniyatlari orqali qisman qamrab olinadi - alohida OT-specific protokollar (Modbus/BACnet) hali qo'shilmagan |
| Rejalashtirilgan + Differensial scan | ✅ **To'liq real test qilingan** (`scheduler.py`) |
| Asset History (qachon qo'shildi/yo'qoldi) | ✅ **To'liq real test qilingan** (`DeviceHistory` jadvali) |

## O'rnatish (tizim darajasidagi vositalar)

```bash
sudo apt install nmap arp-scan iputils-ping snmp
```
(`arp-scan` `ieee-data` paketini avtomatik o'rnatadi - MAC vendor bazasi uchun)

## Ishga tushirish

```bash
# To'liq discovery (ARP + ICMP, ixtiyoriy TCP scan va SNMP boyitish)
python -m network_discovery.asset_inventory --cidr 172.16.0.0/22 --interface eth0 --tcp-scan --snmp

# Topologiya (LLDP/CDP) - kamida 30 soniya kutish tavsiya etiladi
python -m network_discovery.topology_builder --interface eth0 --timeout 60
```

Davriy ishga tushirish uchun cron (masalan har 6 soatda):
```bash
0 */6 * * * cd /path/to/project && python -m network_discovery.asset_inventory --cidr 172.16.0.0/22 --interface eth0
```

## Rejalashtirilgan + Differensial skanerlash (scheduler.py)

To'liq holatni har safar qayta yozish o'rniga, faqat **o'zgargan**
qurilmalarni aniqlaydi: `discovered` (yangi), `disappeared` (24 soatdan
ko'p ko'rinmagan), `reappeared` (qayta paydo bo'lgan). Bu o'zgarishlar
`device_history` jadvaliga yoziladi - Asset History.

```bash
# Bir martalik differensial scan
python -m network_discovery.scheduler --cidr 172.16.0.0/22 --interface eth0 --once

# Doimiy (har soatda)
python -m network_discovery.scheduler --cidr 172.16.0.0/22 --interface eth0 --loop --interval 3600
```

`DISCOVERY_MISSING_THRESHOLD_HOURS` (standart 24) - qurilma necha
soat ko'rinmasa "yo'qolgan" deb belgilanishi.

## Docker'da ishga tushirish (MUHIM: tarmoq rejimi)

Agar Network Discovery **Docker konteynerida** ishga tushirilsa, standart
Docker bridge tarmog'i (`docker-compose.yml`dagi boshqa xizmatlar kabi)
ishlatilmaydi - buning sababi quyida.

### Muammo

Docker o'rnatilgan istalgan production serverda qo'shimcha virtual
interfeyslar bo'ladi (haqiqiy misol):

```
$ ip -4 addr
2: eth0: ... inet 172.16.1.206/22 ...          <- HAQIQIY LAN
3: br-71f7b11dc9c6: ... inet 172.18.0.1/16 ...  <- Docker Compose bridge
4: docker0: ... inet 172.17.0.1/16 ...          <- Docker standart bridge
```

Bu **umumiy tizim ishlashiga** (Dashboard, Syslog Collector, baza)
hech qanday ta'sir qilmaydi - ular oddiy TCP/UDP portlarga bog'langan.

**Lekin** agar `network_discovery` xizmati standart Docker tarmog'ida
ishga tushirilsa, konteyner FAQAT Docker'ning ichki bridge tarmog'ini
(`172.17.x`/`172.18.x`) ko'radi - ARP scan/LLDP capture **noto'g'ri
tarmoqni** (yoki bo'sh natijani) skanerlaydi, haqiqiy LAN'ni (masalan
`172.16.0.0/22`) emas.

### Yechim: `network_mode: host`

`docker-compose.yml`da `network_discovery` xizmati allaqachon
`network_mode: "host"` bilan sozlangan - bu konteynerni host'ning
tarmoq nomfazosiga to'g'ridan-to'g'ri ulaydi (konteyner ichida `ip
addr` host'dagi bilan bir xil natija beradi, jumladan haqiqiy `eth0`).

```bash
# .env faylida:
DISCOVERY_CIDR=172.16.0.0/22
DISCOVERY_INTERFACE=eth0

docker compose --profile discovery up -d network_discovery postgres
```

**Eslatma**: `network_mode: host`da Docker'ning ichki DNS (xizmat
nomi orqali topish, masalan `postgres:5432`) ishlamaydi - shuning
uchun `docker-compose.yml`da bu xizmat uchun `DATABASE_URL`
`127.0.0.1:5432`ga ishora qiladi, va `postgres` xizmati
`127.0.0.1:5432:5432` orqali (faqat localhost'ga, xavfsizlik uchun)
ochilgan.

## Kubernetes Node Discovery

```bash
python -c "from network_discovery.k8s_discovery import discover_k8s_nodes; print(discover_k8s_nodes())"
```
`KUBECONFIG` muhit o'zgaruvchisi yoki `--kubeconfig` parametri orqali
istalgan klaster bilan ishlaydi.

## Muhim texnik eslatmalar

- **Root/CAP_NET_RAW huquqi**: ARP scan, LLDP/CDP capture, va OS
  fingerprinting (`-O`) uchun ko'pincha root huquqi kerak (ICMP va TCP
  connect scan esa oddiy foydalanuvchi huquqida ham ishlaydi).
  Docker Compose'da bu xizmatni `cap_add: [NET_RAW, NET_ADMIN]` bilan
  ishga tushirish tavsiya etiladi.
- **discovery_source ustuvorligi**: agar qurilma ARP orqali (MAC bilan)
  allaqachon topilgan bo'lsa, keyinroq ICMP orqali "kambag'alroq"
  ma'lumot bilan qayta topilishi uning `discovery_source`ini
  "pasaytirmaydi" - bu `asset_inventory.py`da ataylab qilingan (real
  testda tasdiqlangan).
- **AD Discovery filtri**: standart `(objectClass=computer)` haqiqiy
  Microsoft Active Directory uchun to'g'ri. Boshqa LDAP serverlar
  uchun `AD_COMPUTER_FILTER` orqali moslang.
- **UniFi/Kerio**: real controller/server bo'lmasa, bu modullar xato
  ko'tarmasdan bo'sh natija qaytaradi (log'da ogohlantirish bilan) -
  bu ataylab shunday, discovery jarayonini to'xtatib qo'ymaslik uchun.

## CI/test muhiti haqida eslatma

`run_full_test.py`dagi Network Discovery testlari **muhitga
moslashuvchan** - agar kerakli vosita (nmap/arp-scan/slapd) yoki
tarmoq imkoniyati (masalan CAP_NET_RAW) mavjud bo'lmasa, test xato
bermaydi, balki tushunarli xabar bilan o'tkazib yuboradi. Bu loyihaning
boshqa "muhitga bog'liq" testlari (Snort, LDAP, RabbitMQ) bilan bir
xil andoza.
