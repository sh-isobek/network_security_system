# Xodimlar Davomat Monitoring Platformasi — O'rnatish va Sozlash

Bu hujjat `attendance/` subtizimini (Hikvision Face ID terminali
orqali xodimlar davomatini kuzatish, RBAC Dashboard, Telegram/Email
kunlik hisobot) sozlash bo'yicha qo'llanma.

**MUHIM, HALOL CHEKLOV**: bu subtizim shu sessiyada haqiqiy
`194.93.24.92:88` manzilidagi DS-K1T342MFWX terminaliga hech qachon
ulanmagan — ishlab chiqilgan sandbox muhitidan bu IP'ga tarmoq ulanishi
YO'Q (`curl` bilan tekshirilgan, 8 soniyada timeout). Shuning uchun
`attendance/hikvision_client.py` rasmiy Hikvision ISAPI hujjatlariga
mos yozilgan va **lokal, soxta ISAPI serveri** orqali (haqiqiy HTTP
Digest Auth, sahifalab olish, noto'g'ri parolni rad etish — hammasi
haqiqiy HTTP so'rov/javob bilan) to'liq test qilingan
(`attendance/run_attendance_test.py`, SQLite VA PostgreSQL'da).
Haqiqiy qurilmaga qarshi **bir martalik tasdiqlash** terminal bilan
bir xil tarmoqdagi (masalan production serverdan) turib qilinishi
kerak — quyidagi "Haqiqiy qurilmani tekshirish" bo'limiga qarang.

## 1. Arxitektura

```
Hikvision DS-K1T342MFWX (194.93.24.92:88, ISAPI)
        │  (HTTP Digest Auth, AcsEvent qidiruv)
        ▼
attendance/sync_engine.py  --loop   (attn_events jadvaliga yozadi)
        │
        ▼
attendance/calculator.py   --loop   (attn_daily_records: kechikdi/
        │                            vaqtida/erta keldi/kelmadi,
        │                            vaqtida ketdi/erta ketdi/kech ketdi)
        │
        ├──▶ attendance/report_engine.py --loop  (Telegram + Email,
        │                                          har kuni bir marta)
        │
        └──▶ attendance/dashboard/app.py  (Flask, port 8090, RBAC)
```

Barchasi bir xil `DATABASE_URL` (config/settings.py) orqali ishlaydi —
dev'da SQLite, production'da PostgreSQL (asosiy tarmoq xavfsizligi
tizimi bilan BIR XIL bazada, lekin mustaqil `attn_*` jadvallarda).

## 2. Muhit o'zgaruvchilari (`.env`)

`.env.example`dagi "Xodimlar Davomat Monitoring Platformasi" bo'limiga
qarang. Majburiy:
  - `HIKVISION_PASSWORD` — terminal admin paroli.
  - `ATTENDANCE_DASHBOARD_SECRET_KEY` — Dashboard sessiya kaliti.

Ixtiyoriy (standart qiymatlar bilan): `HIKVISION_HOST`/`PORT`/
`USERNAME`, `ATTENDANCE_REPORT_HOUR_LOCAL`, `ATTENDANCE_DEFAULT_WORK_
START`/`END`/`GRACE_*`, `ATTENDANCE_TELEGRAM_BOT_TOKEN`/`CHAT_ID`
(sozlanmasa mavjud `TELEGRAM_BOT_TOKEN`/`CHAT_ID`ga zaxira o'tadi),
`ATTENDANCE_REPORT_EMAILS` (sozlanmasa `ADMIN_EMAIL`ga zaxira o'tadi).

## 3. Ishga tushirish (Docker Compose)

```bash
docker compose up -d attendance_sync attendance_calculator attendance_report attendance_dashboard
```

Bu 4 ta xizmatni ko'taradi (profilsiz emas — standart `docker compose
up -d` bilan avtomatik ISHGA TUSHMAYDI, chunki HIKVISION_PASSWORD
sozlanmagan bo'lsa `sync_engine` jimgina tsiklni o'tkazib yuboradi,
lekin barcha 4 ta xizmatni aniq nomlab ishga tushirish tavsiya etiladi).
Dashboard: `http://<server>:8090`.

## 4. Boshlang'ich super_admin yaratish

```bash
python -m attendance.create_user --username admin --password 'KuchliParol123!' --role super_admin
```

Keyin Dashboard orqali `hr_admin`/`viewer` foydalanuvchilarni
`/users` sahifasidan (faqat super_admin) qo'shish mumkin.

## 5. Rollar (RBAC)

| Rol         | Ko'radi                                              | Qo'sha oladi | O'chira oladi |
|-------------|-------------------------------------------------------|:---:|:---:|
| `viewer`    | FAQAT bosh sahifa: kelish/ketish % va diagrammalar (kechikdi/erta keldi/vaqtida/kelmadi; vaqtida ketdi/erta ketdi/kech ketdi) | ❌ | ❌ |
| `hr_admin`  | Xodimlar (tahrirlash MUMKIN), Oylik hisobotlar, Ogohlantirish/Jarima belgilash | ❌ (xodim qo'shish/o'chirish TAQIQLANGAN — aniq talab) | ❌ |
| `super_admin` | Hammasi + Foydalanuvchilar boshqaruvi + Audit Log (qaysi rol nima bajargani) | ✅ | ✅ |

Har bir muhim amal (`employee_add/delete/edit`, `penalty_add`,
`user_add/deactivate/activate`, `login/logout`) `attn_audit_log`ga
username+rol bilan yoziladi — faqat `super_admin` `/audit` orqali ko'radi.

## 6. Kelish/Ketish statusi qanday hisoblanadi

`attendance/calculator.py`: har bir xodim, har bir ish kuni uchun,
o'sha kundagi BIRINCHI hodisa — "kelish", OXIRGI hodisa — "ketish"
deb olinadi (standart ish jadvali: 09:00–18:00, ±5 daqiqa imtiyoz —
`WorkSchedule` jadvalida moslashtiriladi):

  - Kelish: `erta_keldi` (ish boshlanishidan oldin) / `vaqtida`
    (imtiyoz ichida) / `kechikdi` (imtiyozdan keyin) / `kelmadi`
    (o'sha kun hech qanday hodisa yo'q).
  - Ketish: `vaqtida_ketdi` / `erta_ketdi` / `kech_ketdi`.

**HALOL CHEKLOV**: DS-K1T342MFWX odatda faqat "yuz tanildi" hodisasini
beradi — alohida kirish/chiqish rejimi terminalning o'zida
sozlanmasa, "kelish" va "ketish" bir xil (yoki yagona) hodisadan
hisoblanadi. Kelajakda terminalning `attendanceStatus` maydoni
(agar yoqilgan bo'lsa) orqali aniqroq ajratish mumkin.

## 7. Kunlik hisobot (Telegram/Email)

`attendance/report_engine.py --loop` har kuni (`ATTENDANCE_REPORT_
HOUR_LOCAL` soatida, mahalliy vaqt) KECHAGI kunning kechikish/
kelmaslik ro'yxatini Telegram guruhiga va HR emailiga yuboradi. Bir
kunga BIR MARTA (`attn_daily_report_log` orqali tasdiqlanadi — loop
qayta-qayta ishga tushsa ham takroriy xabar yubormaydi).

Loyihaning o'z tajribasidan olingan saboq (CLAUDE.md'dagi Telegram
xatosi): xabar HECH QACHON `parse_mode="Markdown"` bilan yuborilmaydi —
xodim ismi/bo'limida `[`, `_`, `*` kabi belgilar bo'lsa, Markdown butun
xabarni rad etishi mumkin edi.

## 8. Real test qilish

```bash
python3 -m attendance.run_attendance_test                 # SQLite
export DATABASE_URL="postgresql://postgres:parol@localhost:5432/attendance_test"
python3 -m attendance.run_attendance_test                 # PostgreSQL
```

17/17 test: Hikvision mijozi (real Digest Auth + sahifalash + noto'g'ri
parolni rad etish), Sync Engine (dedup), Kalkulyator (kechikish/erta
kelish/erta ketish/kelmaslik — barcha 4 holat), Statistika, Kunlik
hisobot (Telegram+Email, idempotentlik), RBAC Dashboard (barcha 3 rol,
real HTTP, real DB tekshiruvi bilan — masalan hr_admin'ning xodim
qo'shish/o'chirish urinishi HAQIQATAN 403 va DB'da hech narsa
o'zgarmasligi tasdiqlanadi).

## 9. Haqiqiy qurilmani tekshirish (foydalanuvchi bajarishi kerak)

Terminal bilan bir xil tarmoqdagi (masalan production server) turib:

```bash
curl -s --digest -u admin:PAROL "http://194.93.24.92:88/ISAPI/System/deviceInfo?format=json"
```

Javob `DeviceInfo.model` = `DS-K1T342MFWX` bo'lsa — ulanish to'g'ri,
`.env`ga `HIKVISION_PASSWORD`ni qo'shib `attendance_sync` xizmatini
ishga tushirish mumkin. Keyin `python -m attendance.sync_engine
--since-hours 24` bilan bir martalik orqaga qarab sinxronlashni
qo'lda tekshirish tavsiya etiladi (avval, `--loop`siz).
