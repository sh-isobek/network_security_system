# Windows DNS Server loglarini yuborishni sozlash (NXLog)

Windows o'zi syslog protokolini bilmaydi, shuning uchun DNS so'rovlarini
bizning syslog collector'ga (172.16.x.x:5140 yoki 514) yuborish uchun
**NXLog Community Edition** DNS serverga o'rnatiladi.

## 1. Windows DNS Server'da Analytical logni yoqish

PowerShell (Administrator sifatida, DNS serverda):

```powershell
wevtutil sl "Microsoft-Windows-DNSServer/Analytical" /e:true
```

Bu Event ID 256 (so'rov) va 257 (javob) hodisalarini yoza boshlaydi.

## 2. NXLog o'rnatish va sozlash

`nxlog.conf` fayliga quyidagini qo'shing (yo'l va IP'ni o'zingizga moslang):

```
<Extension json>
    Module xm_json
</Extension>

<Input dns_analytical>
    Module im_msvistalog
    Query <QueryList>\
            <Query Id="0">\
              <Select Path="Microsoft-Windows-DNSServer/Analytical">*[System[(EventID=256)]]</Select>\
            </Query>\
          </QueryList>
    Exec $EventTime = $EventTime;
</Input>

<Output to_collector>
    Module om_udp
    Host 172.16.0.X      # Bizning Python syslog collector IP manzili
    Port 5140            # Yoki production'da 514
    Exec $raw_event = to_json();
</Output>

<Route dns_to_collector>
    Path dns_analytical => to_collector
</Route>
```

**Diqqat:** Yuqoridagi konfiguratsiya soddalashtirilgan namuna. Amalda
`QueryName` va `ClientIP` maydonlarini Windows event strukturasidan
to'g'ri chiqarish uchun NXLog'ning `xm_msvistalog` maydon nomlariga mos
`Exec` qoidalari yozish kerak bo'ladi (masalan `$QueryName = $EventData.QNAME`).
Bu sozlash DNS server tomonidagi tarmoq administratori bilan birgalikda
amalga oshirilishi tavsiya etiladi, chunki Windows Event field nomlari
versiyaga qarab farq qilishi mumkin.

## 3. Kutilayotgan yakuniy format

Bizning `parsers/windows_dns_parser.py` quyidagi JSON tuzilmasini kutadi:

```json
{
  "EventID": 256,
  "ClientIP": "172.16.2.30",
  "QueryName": "malicious-domain.com",
  "QueryType": "A",
  "Timestamp": "2026-07-30T13:05:00Z"
}
```

Agar NXLog boshqa maydon nomlari bilan yozsa, `windows_dns_parser.py`
dagi `data.get("ClientIP")` va `data.get("QueryName")` qatorlarini shu
maydon nomlariga moslab o'zgartiring.
