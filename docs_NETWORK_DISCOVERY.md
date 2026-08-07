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
