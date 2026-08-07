# User Guide

Ushbu qo'llanma Dashboard'dan kundalik foydalanadigan xodimlar
(xavfsizlik analitiklari, kuzatuvchilar) uchun.

## Kirish

1. Brauzeringizda Dashboard manzilini oching (masalan
   `https://security-dashboard.company.local`).
2. Login va parolingizni kiriting.
3. Agar tashkilotingiz MFA yoqilgan bo'lsa, autentifikator ilovangizdagi
   6 xonali kodni kiriting.

Parolingizni unutgan bo'lsangiz, administratoringizga murojaat qiling
(o'zingiz tiklay olmaysiz).

## Bosh sahifa (`/`)

Umumiy holatni ko'rsatadi:
- **Critical/High alertlar soni** — darhol e'tibor talab qiladigan hodisalar
- **Zararli fayllar** — aniqlangan zararli fayllar soni
- **Oxirgi 10 alert** — eng so'nggi hodisalar ro'yxati

## Alertlar (`/alerts`)

Barcha xavfsizlik hodisalari shu yerda. Har bir alert quyidagilarni
ko'rsatadi:
- **Vaqt** va **Daraja** (critical/high/medium/low)
- **Qurilma** — qaysi kompyuter/qurilmada aniqlangan
- **Tafsilot** — nima sodir bo'lgani (masalan "Zararli fayl aniqlandi: invoice.exe")
- **MITRE** — hujum texnikasi kodi (masalan T1204.002)
- **Chora** — tizim avtomatik nima qildi

**Filtrlash**: yuqoridagi tugmalar orqali darajaga qarab filtrlash
mumkin (Critical/High/Medium/Low).

**Tasdiqlash (Acknowledge)**: agar sizda `analyst` yoki `admin` roli
bo'lsa, har bir alert qatorida "Tasdiqlash" tugmasi ko'rinadi. Buni
bosish orqali siz "bu alertni ko'rib chiqdim" deb belgilaysiz - bu
audit log'ga yoziladi.

**Hisobot yuklab olish**: sahifa yuqorisidagi havolalar orqali CSV,
JSON, PDF yoki Excel formatida hisobot yuklab olishingiz mumkin
(7 yoki 30 kunlik davr uchun).

## Qurilmalar (`/devices`)

Tarmoqdagi barcha bilinigan qurilmalar - IP, MAC, hostname, ulanish
turi (Wi-Fi/Kabel), va **Risk Score** (0-100, rang bilan: qizil=yuqori
xavf). Ro'yxat Risk Score bo'yicha saralangan - eng xavfli qurilmalar
tepada.

## Fayllar (`/files`)

Tarmoq orqali o'tgan va tekshirilgan barcha fayllar. "Zararli" yoki
"Toza" deb belgilangan, hash (SHA256) va qaysi manba (mahalliy/VirusTotal/
MalwareBazaar) orqali tekshirilgani ko'rsatiladi.

## Live Map (`/live-map`)

So'nggi 24 soatdagi tarmoq faolligining interaktiv vizual xaritasi.
Har 15 soniyada avtomatik yangilanadi. Node (doira) rangi qurilmaning
Risk Score'iga mos:
- 🔵 Ko'k = xavfsiz
- 🟡 Sariq = o'rtacha xavf
- 🔴 Qizil = yuqori xavf

Sichqoncha bilan ustiga borib turib qo'shimcha ma'lumot (IP, ulanish
turi) ko'rish mumkin.

## MFA sozlash (o'zingiz uchun)

Login qilgandan keyin, navigatsiyadagi "MFA" havolasini bosing:
1. QR-kodni Google Authenticator, Microsoft Authenticator yoki shunga
   o'xshash ilova bilan skanerlang
2. Ilovada ko'rsatilgan 6 xonali kodni kiriting
3. "Yoqish" tugmasini bosing

Endi keyingi safar login qilganingizda, parolingizdan keyin bu kod
ham so'raladi.

## Ruxsatlar farqi (rollar)

| Amal | Viewer | Analyst | Admin |
|---|:---:|:---:|:---:|
| Alertlarni ko'rish | ✅ | ✅ | ✅ |
| Alertni tasdiqlash | ❌ | ✅ | ✅ |
| Hisobot yuklab olish | ✅ | ✅ | ✅ |
| Foydalanuvchi boshqaruvi | ❌ | ❌ | ✅ |
| Audit Log ko'rish | ❌ | ❌ | ✅ |

Agar sizga kerakli tugma ko'rinmasa, bu sizning rolingiz shu amalga
ruxsat bermaganidir - administratoringizga murojaat qiling.
