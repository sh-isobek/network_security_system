# API Guide

Tarmoq Xavfsizligi Monitoring Tizimida ikki xil API mavjud:

1. **Agent API** (`api/server.py`) — Windows/Linux/Mac Endpoint Agentlar
   markaziy server bilan bog'lanadigan REST API.
2. **Dashboard ichki API** (`dashboard/app.py`dagi `/api/*` endpointlar) —
   Web Dashboard'ning frontend (JS) qismi uchun, sessiya-asosli
   autentifikatsiya bilan (Live Map uchun).

---

## 1. Agent API (`api/server.py`)

**Manzil (production)**: `https://<server>:8443` (Docker Compose'da
`agent_api` xizmati, port 8443)

**Autentifikatsiya**: `X-API-Key` sarlavhasi orqali (`.env`dagi
`AGENT_API_KEY` bilan bir xil bo'lishi kerak). Kalit noto'g'ri bo'lsa
`401 Unauthorized` qaytadi.

## Autentifikatsiya usullari (2 xil)

1. **Eski, umumiy kalit** (`AGENT_API_KEY`, `.env`da) — barcha agentlar
   uchun bitta umumiy kalit. Sodda, lekin bitta agent buzilsa hammasini
   bekor qilish kerak bo'ladi.
2. **Yangi, alohida token'lar** (tavsiya etiladi) — har bir
   agent/integratsiya uchun alohida, kuzatiladigan va bekor qilinadigan
   token. Quyida batafsil.

### Alohida API Token yaratish

```bash
python -m api.token_manager --create "ACCOUNTING-PC agent" --expires-days 365
```

Natija (**faqat bir marta ko'rsatiladi**, saqlab qo'ying):
```
Token yaratildi (BU FAQAT BIR MARTA KO'RSATILADI, saqlab qo'ying):
nssk_k-sgszcDDZJlqhy...
```

Bazada faqat SHA256 xesh saqlanadi - token'ning o'zini keyinroq qayta
ko'rsatib bo'lmaydi (parollar kabi).

**Ro'yxat va bekor qilish**:
```bash
python -m api.token_manager --list
python -m api.token_manager --revoke 5
```

**Dashboard orqali** (`/api-tokens`, faqat admin): token yaratish,
ko'rish (yaratilgan/oxirgi ishlatilgan vaqt), bekor qilish - barchasi
Audit Log'ga yoziladi.

### `GET /api/v1/health`

Autentifikatsiyasiz. Server ishlayotganini tekshirish uchun (agentlar
ishga tushganda, monitoring/health-check tizimlari uchun).

**Javob** (200):
```json
{"status": "ok"}
```

### `POST /api/v1/check_hash`

Fayl hash'ini (SHA256) markaziy blacklist va Threat Intel manbalarida
(mahalliy → VirusTotal → MalwareBazaar) tekshiradi.

**So'rov sarlavhasi**: `X-API-Key: <kalit>`

**So'rov tanasi**:
```json
{"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0"}
```

**Javob** (200):
```json
{"malicious": true, "threat_name": "Trojan.GenericKD", "source": "local_blacklist"}
```
`source` qiymatlari: `local_blacklist`, `virustotal`, `malwarebazaar`, yoki `null` (toza bo'lsa).

**Xatolar**:
- `400` — `sha256` noto'g'ri formatda yoki bo'sh
- `401` — API kalit noto'g'ri

### `POST /api/v1/report_incident`

Endpoint Agent lokal ravishda zararli faylni bloklagach, markazga
xabar berish uchun. Bu chaqiruv `Alert` yozuvini yaratadi (Dashboard'da
va bildirishnomalarda ko'rinadi).

**So'rov tanasi**:
```json
{
  "hostname": "ACCOUNTING-PC",
  "ip_address": "172.16.1.45",
  "filename": "invoice.exe",
  "sha256": "275a021b...",
  "threat_name": "Trojan.GenericKD",
  "file_deleted": true,
  "process_killed": true,
  "process_name": "outlook.exe"
}
```
Majburiy maydonlar: `hostname`, `ip_address`, `filename`, `sha256`.

**Javob** (200):
```json
{"status": "recorded", "alert_id": 42}
```

**Xatolar**: `400` — majburiy maydon yo'q.

---

## 2. Dashboard ichki API

Bu endpointlar **sessiya-asosli** (cookie) autentifikatsiya talab
qiladi — `Authorization` sarlavhasi emas, avval `/login` orqali
kirilgan bo'lishi kerak.

### `GET /api/topology`

Live Map uchun tarmoq topologiyasi (JSON: `nodes`, `edges`). Login
talab qiladi (istalgan rol).

### `GET /reports/download?period_days=<N>&format=<csv|json|pdf|excel>`

Hisobotni yuklab olish. Login talab qiladi.

---

## Xato formatlari

Barcha API xatolar quyidagi umumiy formatda qaytadi:
```json
{"error": "Tushuntirish matni"}
```

## Amaliy misol (curl)

```bash
# Health check
curl https://server:8443/api/v1/health

# Hash tekshirish
curl -X POST https://server:8443/api/v1/check_hash \
  -H "X-API-Key: sizning-kalitingiz" \
  -H "Content-Type: application/json" \
  -d '{"sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0"}'
```

## Kengaytirish (Swagger/OpenAPI)

Hozircha rasmiy OpenAPI/Swagger spetsifikatsiyasi yo'q (yangi TZ
15-bo'limida so'ralgan). Buni qo'shish uchun `flask-smorest` yoki
`apiflask` kutubxonasi orqali mavjud route'larni annotatsiyalash
tavsiya etiladi - bu alohida, kelajakdagi ish sifatida qoldirilgan.
