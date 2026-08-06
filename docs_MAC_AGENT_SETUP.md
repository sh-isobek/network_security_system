# macOS Endpoint Agent — o'rnatish yo'riqnomasi

Windows/Linux Agent bilan bir xil yadrodan (`agent_core/`) foydalanadi.

## 1. Fayllarni nusxalash

```bash
sudo mkdir -p /opt/network-security-agent
sudo cp -r agent_core mac_agent config db /opt/network-security-agent/
sudo cp requirements-agent.txt /opt/network-security-agent/
```

## 2. Kutubxonalarni o'rnatish

```bash
cd /opt/network-security-agent
pip3 install -r requirements-agent.txt
```

## 3. `.plist` faylini sozlash

`mac_agent/com.company.network-security-agent.plist` faylini oching va:
- `__AGENT_API_KEY__` — markazdagi bilan bir xil kalitga almashtiring
- `API_SERVER_URL` — markaziy server manzilini tekshiring

## 4. launchd xizmati sifatida o'rnatish

```bash
sudo mkdir -p /usr/local/var/log /usr/local/var/network-security-agent
sudo cp mac_agent/com.company.network-security-agent.plist /Library/LaunchDaemons/
sudo launchctl load /Library/LaunchDaemons/com.company.network-security-agent.plist
```

## 5. Tekshirish

```bash
sudo launchctl list | grep network-security-agent
tail -f /usr/local/var/log/network-security-agent.log
```

## MUHIM: macOS xavfsizlik ruxsatlari

Boshqa foydalanuvchi/ilova jarayonlarini to'xtatish uchun (masalan
Terminal orqali ishga tushirilgan Python) macOS'da qo'shimcha ruxsat
kerak bo'lishi mumkin:

**System Settings > Privacy & Security > Full Disk Access** bo'limiga
`/usr/bin/python3` (yoki agentni ishga tushiruvchi aniq binary yo'lini)
qo'shing.

Agar agent Apple Silicon'da ishlasa va **System Integrity Protection
(SIP)** yoqilgan bo'lsa, ba'zi tizim jarayonlari (masalan Apple'ning
o'z xizmatlari)ni to'xtatish umuman mumkin emas - bu Apple tomonidan
ataylab qo'yilgan cheklov, chetlab o'tib bo'lmaydi. Bu odatda muammo
emas, chunki foydalanuvchi ilovalari (brauzer, Mail, Slack) SIP bilan
himoyalanmagan.

## Cheklov (halol tushuntirish)

Bu yo'riqnoma **kod yozilgan, lekin haqiqiy macOS muhitida sinalmagan**
(loyiha Linux sandbox'da tayyorlangan). `agent_core/`ning o'zi (fayl
kuzatish - watchdog, jarayon boshqarish - psutil) ikkalasi ham rasmiy
ravishda macOS'ni qo'llab-quvvatlaydi, shuning uchun ishlashi kutiladi,
lekin real Mac'da birinchi marta ishga tushirishda `launchctl`
loglarini diqqat bilan tekshiring.
