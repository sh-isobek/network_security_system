# NETGUARD — yangi dizayn (modern + korporativ)

Ushbu paket `dashboard/` papkangiz ustiga yoziladi. Funksional mantiq
(marshrutlar, so'rovlar, JS, CSRF, RBAC, i18n) o'zgartirilmagan —
faqat ko'rinish qatlami qayta yozilgan.

## Nima o'zgardi

- `dashboard/static/dashboard.css` — to'liq qayta yozilgan dizayn tizimi
  (tokenlar, tipografiya, jadval, forma, badge, banner, responsiv).
- `dashboard/templates/base.html` — yangi shell: guruhlangan yon menyu,
  sticky topbar, breadcrumb, foydalanuvchi bloki.
- `dashboard/templates/login.html`, `mfa_verify.html` — ichki `<style>`
  bloklari olib tashlandi, umumiy tizimga o'tildi.
- Qolgan 15 shablon — kartochka/statistika/badge/forma uchun inline
  `style="..."` qiymatlari semantik klasslarga almashtirildi; emoji
  o'rniga CSS bilan chizilgan belgilar.

## O'rnatish

```bash
# loyiha ildizida
unzip netguard-design-templates.zip -d .
# yoki fayllarni qo'lda ko'chiring:
#   dashboard/static/dashboard.css
#   dashboard/templates/*.html
```

Keyin brauzer keshini tozalash (Ctrl+Shift+R) kifoya — qayta build kerak emas.

## Shriftlar

`Public Sans` (matn), `Archivo` (sarlavhalar), `IBM Plex Mono` (raqamlar,
IP/MAC/SHA) serverning o'zidan beriladi: `dashboard/static/fonts/`
(`fonts.css` + woff2 fayllar, latin/latin-ext/kirill qismlari). Brauzer
tashqi internetga (Google Fonts) umuman murojaat qilmaydi — faervol
bloklasa ham sahifa sekinlashmaydi, foydalanuvchi IP'lari tashqariga
chiqmaydi. Litsenziya: SIL Open Font License 1.1 (`LICENSE-*.txt`).

## Eslatma

`dashboard/app.py` dagi `severity_color` filtri o'zgartirilmagan (endi
badge'lar CSS orqali bo'yaladi) — mavjud kod bilan to'liq mos.
