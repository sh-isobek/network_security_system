# Web activity logging extension

**Amalga oshirilgan holat**: hozircha `db.models.WebAccessLog` jadvali
(`collectors/zeek_reader.py` va `engine/parser_engine.py` orqali
to'ldiriladi) faqat quyidagi maydonlarni qamrab oladi: `timestamp`,
`device_id`, `source_ip`, `dest_ip`, `domain`, `url`, `path`, `method`,
`status_code`, `protocol`, `user_agent`, `source`. Bu - Zeek HTTP/SSL/
DNS loglaridan avtomatik to'ldiriladi.

**Quyidagi sxema** - kelajakda proxy/firewall/kategoriya-asosli
manbalar (masalan Squid, pfSense URL filtri) qo'shilganda maqsad
qilingan, **KENGROQ** format (`category`, `action`, `bytes_in/out`,
`username`). Bu hali to'liq amalga oshirilmagan - hozircha faqat
hujjat/kelajak rejasi sifatida saqlanadi.

---

This extension defines a normalized event format for recording which device accessed
which site and when. It is designed to sit behind the existing collectors/API.

Fields:
- timestamp (UTC ISO-8601)
- device_id
- hostname
- ip
- username
- domain
- site
- url
- category
- source
- action (allowed/blocked)
- bytes_in / bytes_out

For reliable attribution, populate `ip` from the network/DHCP source and correlate
it with the endpoint hostname/device ID. Do not infer a URL from DNS alone; DNS only
proves a domain lookup, not necessarily a successful web visit.
