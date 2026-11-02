"""
/etc/suricata/suricata.yaml'ni shu tizim uchun moslaydi (faqat ikkita blok):

1. `outputs: - eve-log:` bloki to'liq almashtiriladi - faqat `alert`,
   `anomaly` va `files` (SHA256/MD5 bilan, `force-hash`) yoziladi.
   Standart sozlama flow/dns/tls/http/... va boshqa 30 ga yaqin turni
   yozardi - bu tarmoqda eve.json kuniga o'nlab GB o'sardi, holbuki
   `collectors/suricata_reader.py` FAQAT `fileinfo` (fayl + SHA256)
   hodisalarini ishlatadi. `force-hash`siz esa fileinfo'da sha256 umuman
   bo'lmaydi va reader hech bir faylni olmaydi.
2. `outputs: - stats:` (stats.log) o'chiriladi - har 8 soniyada yozilib,
   production'da 9.7 GB'ga yetgan edi.

Faylning QOLGAN qismi bayt-bayt o'zgarmaydi (YAML qayta yozilmaydi -
PyYAML izohlarni yo'qotar va `0644`/`1:30` kabi qiymatlarni buzardi).
Idempotent: qayta ishga tushirilsa, natija bir xil bo'ladi.

Ishlatish:  python3 configure_suricata.py <kirish.yaml> <chiqish.yaml>
"""
import re
import sys

MARKER = "# network_security_system: eve-log (configure_suricata.py)"

EVE_BLOCK = f"""  {MARKER}
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            tagged-packets: yes
        - anomaly:
            enabled: yes
        - files:
            force-magic: yes
            force-hash: [sha256, md5]
"""

_ITEM = re.compile(r"^  - ([A-Za-z0-9_-]+):\s*$")
_TOP_LEVEL = re.compile(r"^\S")


def _outputs_items(lines):
    """outputs: ro'yxatidagi har bir element uchun (nom, boshlanish, tugash) qaytaradi."""
    start = next(i for i, line in enumerate(lines) if line.rstrip("\n") == "outputs:")
    end = next((i for i in range(start + 1, len(lines)) if _TOP_LEVEL.match(lines[i])), len(lines))
    items, current = [], None
    for i in range(start + 1, end):
        m = _ITEM.match(lines[i].rstrip("\n"))
        if m:
            if current:
                items.append((current[0], current[1], i))
            current = (m.group(1), i)
    if current:
        items.append((current[0], current[1], end))
    return items


def _trim_trailing_comments(lines, begin, end):
    """Blok oxiridagi keyingi elementga tegishli izoh/bo'sh qatorlarni blokdan chiqaradi."""
    while end > begin + 1 and (not lines[end - 1].strip() or lines[end - 1].lstrip().startswith("#")):
        end -= 1
    return end


def configure(text: str) -> str:
    lines = text.splitlines(keepends=True)
    items = _outputs_items(lines)

    eve = [it for it in items if it[0] == "eve-log"]
    if len(eve) != 1:
        raise SystemExit(f"Kutilgan 1 ta eve-log bloki, topildi: {len(eve)}")
    _name, begin, end = eve[0]
    end = _trim_trailing_comments(lines, begin, end)
    if begin > 0 and lines[begin - 1].strip() == MARKER:
        begin -= 1
    lines[begin:end] = [EVE_BLOCK]

    for name, begin, end in _outputs_items(lines):
        if name != "stats":
            continue
        for i in range(begin + 1, end):
            if re.match(r"^      enabled:\s*\S+", lines[i]):
                lines[i] = re.sub(r"enabled:\s*\S+", "enabled: no", lines[i], count=1)
                break
        else:
            raise SystemExit("stats chiqishida 'enabled:' qatori topilmadi")
    return "".join(lines)


if __name__ == "__main__":
    src, dst = sys.argv[1], sys.argv[2]
    with open(src, encoding="utf-8") as fh:
        result = configure(fh.read())
    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(result)
