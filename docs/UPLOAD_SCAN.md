# Endpoint fayllarini vaqtinchalik tekshirish

`check_hash` shubhali yoki noma'lum natija uchun `upload_required: true`
qaytaradi. Agent 1.0.14 shu faylni `POST /api/v1/scan_file` orqali yuboradi.
Chegara: 25 MiB. Katta yoki o'qib bo'lmaydigan fayl uchun avvalgi xesh va
mahalliy tahlil qarori saqlanadi. Eski server/agent bilan xesh protokoli mos.

Yuklash formati `application/octet-stream`, `Content-Length` bilan. Sarlavhalar:
`X-API-Key`, `X-Agent-Hostname`, `X-File-SHA256`, `X-File-Name` (URL-encoded).
Agentga bog'langan token uchun hostname tekshiriladi. Limit: token boshiga
daqiqada 6 yuklash. Server xeshni o'zi qayta hisoblaydi.

Server YARA, ClamAV va mavjud APK/PDF/Office/statik tahlilni ishlatadi.
Yuklangan arxiv a'zolari alohida disk fayllariga chiqarilmaydi; ClamAV ichki
arxiv tekshiruvini bajarishi mumkin. Bu dinamik sandbox emas. ClamAV mavjud
bo'lmasa yoki xato bersa, `scan_complete: false`; belgisiz fayl `unknown`
bo'lib qoladi. Heuristik ballning o'zi server javobida `confirmed` bermaydi.
Agentning avvalgi mahalliy karantin siyosati o'zgarmaydi.

Har so'rov o'zining tasodifiy vaqtinchalik katalogida ishlaydi. Muvaffaqiyat,
xesh xatosi, hajm oshishi, uzilish yoki skaner exception holatida context
manager katalogni o'chiradi. Javob va DB yozuvi faqat o'chirishdan keyin
bajariladi. O'chirish xatosi 200 javobga yashirilmaydi. Server bu namunani
karantinga, backupga yoki deep-scan navbatiga ko'chirmaydi. DB'da xesh,
natija va mavjud FileEvent sxemasi talab qiladigan manba IP/vaqt qoladi;
namuna yo'li va fayl mazmuni saqlanmaydi. Agentning o'z karantini alohida.

Docker Compose va Kubernetes `/tmp` uchun vaqtinchalik RAM volume ishlatadi.
`UPLOAD_SCAN_ROOT` standart `/tmp/endpoint-scans`; uni persistent volume yoki
backup olinadigan katalogga yo'naltirmang. Nginx request buffering o'chirilgan;
qo'shimcha reverse proxy bo'lsa, unda ham upload bufferingni o'chiring.
ClamAV bazasi o'rnatilib, yangilanib turishi kerak. TLS uchun mavjud ichki
CA sozlamalaridan foydalaning; sertifikat tekshiruvi o'chirilmaydi.

Cheklov: `SIGKILL`, worker majburiy o'ldirilishi yoki OS qulashi Python cleanup
kodini ishlatmaydi; qolgan vaqtinchalik nusxalar volume yo'q qilinguncha
qolishi mumkin. tmpfs swapga chiqishi mumkin: qat'iy diskda iz qoldirmaslik
talabi uchun host swap/core dump siyosatini ham sozlash kerak. Oddiy fayl
o'chirish SSD/snapshotdan kriptografik qayta tiklanmaslik kafolati emas.

Tekshirish: `python -m unittest test_upload_scan -v`. Xuddi shu testlar
`run_full_test.py` tarkibiga ham kiritilgan. SQLite yoki alohida PostgreSQL
test bazasi uchun `DATABASE_URL` sozlanadi. Production bazasida test
to'plamini ishlatmang.
