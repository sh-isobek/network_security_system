"""
Xodimlar Davomat Monitoring Platformasi (Face ID asosida).

Bu - `network_security_system`ning asosiy tarmoq xavfsizligi
domenidan MUSTAQIL, alohida subtizim: Hikvision Face ID terminali
(DS-K1T342MFWX, 194.93.24.92:88) orqali xodimlarning kelish/ketish
vaqtini kuzatadi, kechikish/kelmaslikni aniqlaydi, Telegram/Email
orqali avtomatik kunlik hisobot yuboradi, va RBAC (super_admin/
hr_admin/kuzatuvchi) bilan Dashboard taqdim etadi.

Loyihaning umumiy pattern'iga amal qiladi:
  - `models.py`  - SQLAlchemy ORM (alohida, mustaqil `Base`)
  - `database.py`- `get_session()` markaziy nuqta
  - `hikvision_client.py` - ISAPI mijozi
  - `sync_engine.py`      - run_once()/run_loop() (qurilmadan DB'ga)
  - `calculator.py`       - kunlik status hisoblash (kechikdi/erta
                             keldi/erta ketdi/vaqtida/kelmadi)
  - `report_engine.py`    - Telegram/Email kunlik hisobot
  - `dashboard/app.py`    - Flask + flask-login, 3 rol
"""
