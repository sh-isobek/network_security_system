#!/usr/bin/env bash
# Suricata'ni shu tizim uchun tuzatadi (host'da, root sifatida):
#   sudo bash deploy/suricata/fix_suricata.sh
#
# 1. /etc/suricata/suricata.yaml zaxiralanadi, configure_suricata.py bilan
#    faqat eve-log (alert/anomaly/files + SHA256) va stats.log bloklari
#    o'zgartiriladi, `suricata -T` bilan tekshiriladi - xato bo'lsa hech
#    narsa o'zgarmaydi.
# 2. Docker tasodifan yaratgan bo'sh /var/log/suricata/eve.json PAPKASI
#    o'chiriladi (Suricata 18-avgustdan beri eve.json'ni yoza olmasdi).
# 3. /etc/logrotate.d/suricata o'rnatiladi (stats.log 9.7 GB'ga yetgan edi).
# 4. Suricata qayta ishga tushiriladi va eve.json fayl ekani tekshiriladi.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONF=/etc/suricata/suricata.yaml
LOGDIR=/var/log/suricata
STAMP="$(date +%Y%m%d-%H%M%S)"

[ "$(id -u)" -eq 0 ] || { echo "root kerak: sudo bash $0"; exit 1; }
command -v suricata >/dev/null || { echo "suricata o'rnatilmagan"; exit 1; }

echo "== 1/4 suricata.yaml"
cp -a "$CONF" "$CONF.bak-$STAMP"
echo "   zaxira: $CONF.bak-$STAMP"
python3 "$HERE/configure_suricata.py" "$CONF" "$CONF.new"
# -T ham chiqish fayllarini ochadi: haqiqiy /var/log/suricata'da (u yerda
# hali soxta eve.json papkasi bo'lishi mumkin; root yaratgan eve.json'ga esa
# keyin `suricata` foydalanuvchisi yoza olmaydi) emas, vaqtinchalik papkada.
TESTDIR="$(mktemp -d)"
if ! suricata -T -c "$CONF.new" -l "$TESTDIR" >"$TESTDIR/configtest.log" 2>&1; then
    echo "   XATO: yangi sozlama tekshiruvdan o'tmadi - o'zgartirilmadi:"
    tail -n 15 "$TESTDIR/configtest.log"
    rm -f "$CONF.new"
    rm -rf "$TESTDIR"
    exit 1
fi
rm -rf "$TESTDIR"
chown --reference="$CONF" "$CONF.new"
chmod --reference="$CONF" "$CONF.new"
mv "$CONF.new" "$CONF"
echo "   OK: eve.json = alert + anomaly + files (sha256/md5), stats.log o'chirildi"

echo "== 2/4 $LOGDIR/eve.json"
if [ -d "$LOGDIR/eve.json" ]; then
    if [ -z "$(ls -A "$LOGDIR/eve.json")" ]; then
        rmdir "$LOGDIR/eve.json"
        echo "   bo'sh papka o'chirildi"
    else
        echo "   XATO: $LOGDIR/eve.json bo'sh bo'lmagan papka - qo'lda tekshiring"
        exit 1
    fi
else
    echo "   papka emas - o'zgartirish shart emas"
fi

echo "== 3/4 logrotate"
install -m 0644 -o root -g root "$HERE/logrotate-suricata" /etc/logrotate.d/suricata
logrotate -d /etc/logrotate.d/suricata >/dev/null 2>&1 && echo "   /etc/logrotate.d/suricata o'rnatildi"
if [ -f "$LOGDIR/stats.log" ]; then
    SIZE=$(du -h "$LOGDIR/stats.log" | cut -f1)
    mv "$LOGDIR/stats.log" "$LOGDIR/stats.log.old-$STAMP"
    echo "   eski stats.log ($SIZE) -> stats.log.old-$STAMP (kerak bo'lmasa o'chiring)"
fi

echo "== 4/4 Suricata qayta ishga tushirilmoqda"
systemctl restart suricata
for _ in $(seq 60); do
    [ -f "$LOGDIR/eve.json" ] && break
    sleep 1
done
systemctl is-active suricata
if [ -f "$LOGDIR/eve.json" ]; then
    echo "   OK: $LOGDIR/eve.json fayl sifatida yaratildi"
else
    echo "   OGOHLANTIRISH: eve.json hali yaratilmadi - journalctl -u suricata ni tekshiring"
fi
grep -E "eve-log|eve.json" "$LOGDIR/suricata.log" | tail -n 3 || true
echo
echo "Tayyor. Zaxirani qaytarish: sudo cp -a $CONF.bak-$STAMP $CONF && sudo systemctl restart suricata"
