# Alembic Migration Tizimi

## Nima uchun kerak edi

Ilgari baza sxemasi faqat `db/models.py::init_db()` orqali boshqarilgan:
`Base.metadata.create_all()` (FAQAT yangi jadval yaratadi) + `_sync_missing_columns()`
("kamtarona migratsiya" - mavjud jadvalga yetishmayotgan NULLABLE ustunlarni
avtomatik `ALTER TABLE ... ADD COLUMN` bilan qo'shadi).

Bu yondashuv ishlab keldi, lekin haqiqiy rasmiy migratsiya tarixi (versiya
raqamlangan, orqaga qaytarish mumkin bo'lgan, avtomatik tekshiriladigan)
yo'q edi. `_sync_missing_columns()` **butunlay olib tashlanmadi** - u
hamon `init_db()` ichida ishlaydi (backward-compat/xavfsizlik to'ri
sifatida). Endi esa Alembic **rasmiy, tekshiriladigan** yo'l hisoblanadi.

## Fayl tuzilishi

```
alembic.ini          - sozlama (sqlalchemy.url YOZILMAGAN - env.py orqali dinamik)
alembic/
  env.py             - DATABASE_URL'ni config/settings.py'dan o'qiydi
  script.py.mako     - yangi migratsiya shabloni
  versions/
    c15ffeb890b8_initial_schema_baseline.py   - joriy (2026-09-16) sxemaning to'liq bazasi
```

`alembic/env.py` `config/settings.py::DATABASE_URL`dan foydalanadi - bu
loyihaning BOSHQA barcha qismi (dashboard, engine'lar, agent API) bilan
bir xil yagona manba. Demak:

```bash
alembic upgrade head                                    # standart: sqlite:///./logs/security_system.db
DATABASE_URL="postgresql://user:pass@host:5432/db" alembic upgrade head   # PostgreSQL
```

## Yangi sxema o'zgarishi qanday qilinadi (BUNDAN BUYON)

1. `db/models.py`ga yangi ustun/jadval qo'shiladi (odatdagidek).
2. Migratsiya avtomatik generatsiya qilinadi:
   ```bash
   export DATABASE_URL="sqlite:///./logs/security_system.db"   # yoki dev Postgres
   alembic revision --autogenerate -m "qisqa_tavsif"
   ```
3. Generatsiya qilingan faylni (`alembic/versions/<hash>_qisqa_tavsif.py`)
   **albatta qo'lda ko'rib chiqiladi** - autogenerate ba'zan noto'g'ri
   taxmin qilishi mumkin (masalan ustun nomini o'zgartirish `drop`+`add`
   sifatida ko'rinadi, `server_default` kerak bo'lgan holatlar va h.k.).
4. Test:
   ```bash
   alembic upgrade head      # SQLite'da
   # keyin alohida, vaqtinchalik Docker PostgreSQL konteynerida ham
   ```
5. `run_full_test.py`dagi "92) Alembic..." testi CI'da avtomatik
   tekshiradi: bo'sh bazada `upgrade head`dan keyingi sxema **aynan**
   `db/models.py`dagi modellarga mos kelishi kerak (drift bo'lsa test
   ushlaydi - bu xuddi "column X does not exist" xatosining oldindan
   ogohlantiruvchi versiyasi).

## MUHIM: production bazasini Alembic nazoratiga o'tkazish (BIR MARTALIK qadam)

Production baza (va har qanday mavjud dev/staging baza) Alembic'dan
OLDIN, `init_db()` orqali yaratilgan - unda ALLAQACHON barcha jadval/
ustunlar bor. Bunday bazada **`alembic upgrade head` ISHLATILMAYDI**
(u jadvallarni QAYTA yaratishga urinib, "table already exists" xatosi
bilan MUVAFFAQIYATSIZ bo'ladi). Buning o'rniga:

```bash
# Faqat versiya belgisini qo'yadi - HECH QANDAY DDL bajarmaydi
export DATABASE_URL="postgresql://<production credentiallari>"
alembic stamp head
```

Bu `alembic_version` jadvalini yaratib, unga joriy baseline revision
ID'sini (`c15ffeb890b8`) yozadi - bazaning o'zi bir amallik ham
o'zgarmaydi. Shundan keyin production baza "Alembic nazoratida" deb
hisoblanadi - kelajakdagi barcha yangi migratsiyalar endi
`alembic upgrade head` orqali qo'llanishi mumkin.

**Bu qadam `run_full_test.py`da "93) ...stamp head..." testi orqali
sintetik (legacy `init_db()` orqali yaratilgan) bazada to'liq
tasdiqlangan** - lekin haqiqiy production bazasiga qarshi ATAYLAB
BU SESSIYADA BAJARILMADI (real production ma'lumot bazasiga tegish -
hatto faqat metadata yozish bo'lsa ham - alohida, ongli tasdiq talab
qiladi).

## Katta jadvalga indeks qo'shish (`CREATE INDEX CONCURRENTLY`)

Production'dagi `events`/`raw_logs`/`web_access_logs` millionlab
qatorga ega (masalan `events` - 7.6 million+). Bunday jadvalga oddiy
`op.create_index()` PostgreSQL'da butun jadvalni YOZISH uchun
BLOKLAB qo'yadi (parser_engine kabi doimiy yozuvchi jarayonlar
sekundlar-daqiqalar davomida to'xtab qoladi). Buning o'rniga:

```python
def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        with op.get_context().autocommit_block():
            op.create_index(
                "ix_...", "jadval", ["ustun"],
                postgresql_concurrently=True,
            )
    else:
        op.create_index("ix_...", "jadval", ["ustun"])  # SQLite: CONCURRENTLY yo'q, kerak ham emas
```

`CONCURRENTLY` tranzaksiya ICHIDA ishlay olmaydi - shuning uchun
`op.get_context().autocommit_block()` orqali Alembic'ning odatiy
tranzaksiyasidan chetga chiqariladi. Misol: `alembic/versions/
60a696c5452e_add_alert_and_event_performance_indexes.py`
(`ix_events_device_id_timestamp`).

## Halol cheklovlar

- `_sync_missing_columns()` hali ham `init_db()` ichida ishlaydi -
  bu ATAYLAB shunday qoldirildi (`run_full_test.py`dagi ko'plab
  eski testlar bevosita `init_db()`ni chaqiradi, Alembic orqali emas -
  ularni ham Alembic'ga o'tkazish alohida, kattaroq ish). Amalda bu
  xavfsiz: ikkalasi ham bir xil `db/models.py`dan kelib chiqadi, va
  "92-94" testlari ularning doim SINXRON qolishini kafolatlaydi.
- Autogenerate ba'zi murakkab o'zgarishlarni (ustun nomini o'zgartirish,
  ma'lumotni ko'chirish talab qiladigan o'zgarishlar) to'g'ri
  taxmin QILA OLMAYDI - bunday holatlarda migratsiya qo'lda yoziladi/
  tuzatiladi (Alembic hujjatlarida keng yoritilgan, standart holat).
