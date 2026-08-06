# Docker Compose orqali joriy etish

## Nima konteynerlashtirilgan, nima emas

**Konteynerlashtirilgan** (`docker-compose.yml` orqali):
- PostgreSQL baza
- Barcha Python xizmatlar (syslog_collector, parser_engine,
  file_analysis_engine, deep_scan_engine, response_engine,
  notification_engine, mitre_tagging_engine, agent_api, dashboard)
- ClamAV virus bazasi yangilovchisi

**Konteynerlashtirilmagan** (host'da alohida ishlaydi):
- **Suricata** — SPAN port orqali xom tarmoq trafigini o'qishi kerak,
  bu odatda host tarmog'iga to'g'ridan-to'g'ri kirishni talab qiladi
  (`docs_SURICATA_SETUP.md`ga qarang). Uning `file-store` chiqishi
  `deep_scan_engine` konteyneriga bind-mount orqali beriladi.
- **Kerio Control, switchlar, UniFi Controller** — bular alohida
  jismoniy/virtual qurilmalar, tarmoq infratuzilmasining bir qismi.
- **Windows va Linux Endpoint Agent** (`windows_agent/`, `linux_agent/`,
  umumiy yadro `agent_core/`) — foydalanuvchi kompyuterlarida/serverlarida
  ishlaydi, Docker bilan aloqasi yo'q (`docs_WINDOWS_AGENT_SETUP.md`,
  `docs_LINUX_AGENT_SETUP.md`ga qarang).

## Muhim: bu haqiqiy Docker'da sinalmagan (lekin PostgreSQL'da sinalgan)

Ushbu loyiha tayyorlangan muhitda Docker daemon mavjud emas edi, shuning
uchun `docker-compose up` buyrug'ining o'zi ishga tushirilmadi. **Lekin**
butun tizim (barcha 14 ta test) **haqiqiy PostgreSQL serverida** (Docker
Compose'da ishlatiladigan xuddi shu baza turi) muvaffaqiyatli sinovdan
o'tkazildi — shuning uchun `DATABASE_URL=postgresql://...` bilan ishlashi
yuqori ishonch bilan kutiladi. `docker-compose.yml` va `Dockerfile`
qo'lda diqqat bilan ko'rib chiqilgan (YAML sintaksisi tekshirilgan).

**Birinchi marta ishga tushirishda quyidagilarni tekshiring:**
```bash
docker compose config          # YAML va o'zgaruvchilarni tekshirish
docker compose up -d postgres  # avval faqat bazani ishga tushiring
docker compose logs postgres   # sog'lom ishga tushganini tekshiring
docker compose up -d           # qolganlarini ishga tushiring
docker compose logs -f         # loglarni kuzatish
```

## O'rnatish

```bash
cp .env.example .env
# .env faylini oching, kamida quyidagilarni to'ldiring:
#   POSTGRES_PASSWORD, AGENT_API_KEY, DASHBOARD_PASSWORD

docker compose up -d --build
```

## Birinchi admin foydalanuvchini yaratish (RBAC)

Dashboard endi login-asosli (Basic Auth emas). Konteynerlar ishga
tushgandan keyin birinchi admin foydalanuvchini yarating:

```bash
docker compose exec dashboard python -m dashboard.create_user \
    --username admin --password 'KuchliParol123!' --role admin
```

## Xizmatlarni tekshirish

```bash
docker compose ps
```

Dashboard: http://<server-ip>:8080 (login: `.env`dagi DASHBOARD_USERNAME/PASSWORD)
Agent API: http://<server-ip>:8443/api/v1/health

## Suricata file-store'ni ulash

`docker-compose.yml`da `deep_scan_engine` xizmati quyidagi qatorni
o'z ichiga oladi:
```yaml
volumes:
  - /var/log/suricata/files:/var/log/suricata/files:ro
```

Agar Suricata boshqa serverda ishlasa, bu papkani NFS/SMB orqali
ulashingiz yoki `rsync` bilan davriy nusxalashingiz kerak bo'ladi.

## Kengaytirish (keyingi bosqichlar uchun tayyor joy)

- **Kafka/RabbitMQ** (yangi TZ 17-bo'lim): hozircha enginelar oddiy
  polling (`--loop --interval N`) orqali ishlaydi. Yuqori yuklama
  (100 000+ events/sec) uchun bu xizmatlar orasiga message queue
  qo'shish kerak bo'ladi - bu alohida, kattaroq refaktoring ishi.
- **Kubernetes**: `docker-compose.yml`dagi har bir xizmat deyarli
  to'g'ridan-to'g'ri bitta Kubernetes Deployment'ga mos keladi
  (barchasi stateless, DATABASE_URL orqali bazaga ulanadi) - lekin
  Suricata/ClamAV kabi host-darajasidagi bog'liqliklar sabab, to'liq
  K8s manifestlarini alohida ishlab chiqish kerak.
- **Horizontal scaling**: `file_analysis_engine`, `deep_scan_engine`
  kabi xizmatlarni bir nechta nusxada ishga tushirish mumkin (`docker
  compose up -d --scale file_analysis_engine=3`) - chunki ular
  navbat-asosida (`checked=False`) ishlaydi va bir-birining ustidan
  yozmaydi (SQL `LIMIT` + tranzaksiya orqali).
