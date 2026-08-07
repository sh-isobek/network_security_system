# Disaster Recovery (DR) Guide

## Maqsad

Ushbu hujjat tizim butunlay ishdan chiqqan (server halokati, ma'lumotlar
bazasi buzilishi, tasodifiy o'chirish) taqdirda xizmatni tiklash
tartibini belgilaydi.

## RPO/RTO maqsadlari (tavsiya etiladigan)

| Ko'rsatkich | Maqsad | Izoh |
|---|---|---|
| **RPO** (Recovery Point Objective) | 24 soat | Kunlik avtomatik backup bilan |
| **RTO** (Recovery Time Objective) | 1 soat | Docker Compose'da; K8s'da tezroq (avtomatik qayta ishga tushirish) |

Tashkilotingiz xavfsizlik siyosatiga qarab bu qiymatlarni qattiqroq
qilish uchun backup chastotasini oshiring (masalan har 4 soatda).

## 1. Avtomatik backup sozlash

`backup/backup_manager.py` SQLite va PostgreSQL'ni avtomatik aniqlaydi.

**Cron orqali (Docker Compose/oddiy server)**:
```bash
# /etc/cron.d/security-system-backup
0 2 * * * root cd /path/to/network_security_system && \
    docker compose exec -T postgres pg_isready && \
    python -m backup.backup_manager --backup --output-dir /mnt/backups
```

**Kubernetes CronJob** (namuna):
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: db-backup
  namespace: network-security
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: backup
              image: ghcr.io/your-org/network-security-system:latest
              command: ["python", "-m", "backup.backup_manager", "--backup"]
              envFrom:
                - configMapRef: {name: app-config}
                - secretRef: {name: app-secrets}
              volumeMounts:
                - {name: backup-storage, mountPath: /app/backups}
          volumes:
            - name: backup-storage
              persistentVolumeClaim: {claimName: backup-pvc}
          restartPolicy: OnFailure
```

**MUHIM**: backup fayllarini **boshqa fizik joyga** (masalan S3,
tashqi NAS) muntazam ko'chirib turing - agar backup asosiy server bilan
bir joyda saqlansa, server halokati backup'ni ham yo'qotadi.

## 2. Halokat stsenariylari va tiklash tartibi

### Stsenariy A: Ma'lumotlar bazasi buzilgan/yo'qolgan (server tirik)

```bash
# 1) Eng so'nggi backup'ni topish
python -m backup.backup_manager --list

# 2) Xizmatlarni to'xtatish (yozishni to'xtatish uchun)
docker compose stop parser_engine file_analysis_engine deep_scan_engine \
    response_engine notification_engine mitre_tagging_engine ueba_engine

# 3) Tiklash
python -m backup.backup_manager --restore /path/to/backup_YYYYMMDD_HHMMSS.sql

# 4) Xizmatlarni qayta ishga tushirish
docker compose start parser_engine file_analysis_engine deep_scan_engine \
    response_engine notification_engine mitre_tagging_engine ueba_engine
```

### Stsenariy B: Butun server yo'qolgan (to'liq qayta qurish)

```bash
# 1) Yangi serverda loyihani klon qilish
git clone https://github.com/sh-isobek/network_security_system.git
cd network_security_system

# 2) .env faylini tiklash (parol menejeridan/maxfiy backup'dan)
cp .env.backup .env

# 3) Bazasiz xizmatlarni ko'tarish
docker compose up -d postgres
sleep 10

# 4) Backup'dan tiklash (eng so'nggi, tashqi saqlagichdan olingan)
python -m backup.backup_manager --restore /path/to/latest_backup.sql

# 5) Qolgan barcha xizmatlarni ishga tushirish
docker compose up -d

# 6) Tekshirish
python3 run_full_test.py
docker compose logs -f
```

### Stsenariy C: Tasodifan noto'g'ri ma'lumot o'chirilgan/o'zgartirilgan

Agar butun bazani emas, faqat bitta yozuvni tiklash kerak bo'lsa:
```bash
# Backup'ni VAQTINCHA boshqa bazaga tiklang (joriy bazani buzmasdan)
createdb temp_restore_db
DATABASE_URL="postgresql://user:pass@localhost/temp_restore_db" \
    python -m backup.backup_manager --restore /path/to/backup.sql

# Kerakli yozuvni qo'lda (psql yoki SQLAlchemy orqali) asosiy bazaga ko'chiring
```

## 3. Tiklashni davriy sinash (MUHIM)

Backup'ning o'zi yetarli emas - **muntazam ravishda tiklashni sinab
turish kerak** (masalan har chorakda), aks holda backup buzilgan
bo'lishi mumkinligini faqat haqiqiy halokat paytida bilib qolasiz.

```bash
# Test muhitida (production'ga tegmasdan):
createdb dr_test_db
DATABASE_URL="postgresql://user:pass@localhost/dr_test_db" \
    python -m backup.backup_manager --restore /path/to/latest_backup.sql
DATABASE_URL="postgresql://user:pass@localhost/dr_test_db" \
    python3 -c "from db.database import get_session; from db.models import Alert; print(get_session().query(Alert).count(), 'ta alert tiklandi')"
dropdb dr_test_db
```

Bu loyihaning `run_full_test.py`sida aynan shu turdagi "halokat
simulyatsiyasi → backup → tiklash → tekshirish" sikli avtomatik test
qilingan - siz ham xuddi shu naqshni production backup'laringiz uchun
qo'llashingiz mumkin.

## 4. Aloqa va eskalatsiya

Real tashkilotda bu bo'limga quyidagilar qo'shilishi kerak:
- Kimga qo'ng'iroq qilish kerak (on-call jadval)
- Qaysi Slack/Teams kanalida e'lon qilish
- Qachon boshqaruvni xabardor qilish kerak (masalan RTO 1 soatdan
  oshsa)

Bu tashkilot-specifik ma'lumot bo'lgani uchun shablon sifatida
qoldirilgan - to'ldirib chiqing.
