# Grafana va Live Map (yangi TZ 12-bo'lim: Dashboard)

## Live Map — to'liq ishlaydi (mavjud Dashboard'da)

Yangi sahifa: `/live-map` — interaktiv tarmoq topologiyasi grafigi
(`vis-network` kutubxonasi, CDN orqali). So'nggi 24 soatda faol
qurilmalarni va ularning tashqi aloqalarini ko'rsatadi:
- **Node rangi** = Risk Score (qizil=yuqori, sariq=o'rta, ko'k=past/yo'q)
- **Edge qalinligi** = hodisalar soni
- Har 15 soniyada avtomatik yangilanadi (`/api/topology` JSON endpoint)

**Real test qilingan**: haqiqiy ma'lumot bilan (risk_score=75 va
risk_score=10 bo'lgan ikkita qurilma), `/api/topology` to'g'ri rang,
o'lcham va edge sonini qaytarganligi tasdiqlangan.

## Grafana — halol cheklov bilan

Grafana rasmiy ravishda faqat `dl.grafana.com` (o'z CDN'i) orqali
tarqatiladi - GitHub release'larida binary biriktirilmagan (faqat
manba kod tegi). Bu domen ushbu loyiha tayyorlangan sandbox muhitida
ruxsat etilgan domenlar ro'yxatida yo'q edi, shuning uchun **Grafana'ning
o'zi bu yerda o'rnatilmagan va ishga tushirilmagan** (Zeek bilan bir xil
holat).

**Nima qilindi va sinaldi**:
- `grafana/dashboards/security-overview.json` — 8 panelli tayyor
  dashboard (Grafana'ning rasmiy JSON sxemasiga mos)
- `grafana/provisioning/` — datasource va dashboard avtomatik yuklash
  konfiguratsiyasi
- **Barcha 8 ta SQL so'rov haqiqiy PostgreSQL bazamizga qarshi ijro
  etilib, to'g'ri ma'lumot qaytarishi tasdiqlangan** (Grafana'ning o'zi
  bo'lmasa ham, SQL sintaksisi va mantiqiy to'g'riligi 100% tekshirilgan)

## Panellar

| Panel | Turi | Nima ko'rsatadi |
|---|---|---|
| Jami Critical Alertlar (24 soat) | Stat | So'nggi kunlik critical alertlar |
| Jami Qurilmalar | Stat | Umumiy qurilmalar soni |
| Zararli Fayllar (jami) | Stat | `verdict='malicious'` fayllar |
| Xabar Berilmagan Alertlar | Stat | `notified=false` alertlar |
| Vaqt bo'yicha Alertlar (Severity) | Time series | Soatlik trend, severity bo'yicha |
| MITRE ATT&CK Taktika Taqsimoti | Pie chart | Taktikalar bo'yicha taqsimot |
| Eng Yuqori Risk Score'li Qurilmalar | Bar gauge | Top-10 xavfli qurilma |
| So'nggi Alertlar | Table | Oxirgi 50 ta alert, to'liq tafsilot |

## O'rnatish (production, internetga kirish imkoni bo'lganda)

```bash
docker compose --profile grafana up -d grafana
```

Kirish: http://localhost:3000 (login: `admin`, parol: `.env`dagi
`GRAFANA_ADMIN_PASSWORD`). Dashboard avtomatik yuklanadi (`Xavfsizlik`
papkasida) - provisioning orqali, qo'lda import qilish shart emas.

## .env sozlamasi

```
GRAFANA_ADMIN_PASSWORD=KuchliParol123!
```
