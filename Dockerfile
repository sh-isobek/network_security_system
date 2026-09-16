# Tarmoq Xavfsizligi Monitoring Tizimi - Docker image
#
# Bitta image barcha Python xizmatlar (collector, parser, enginelar,
# API, dashboard) uchun ishlatiladi - docker-compose.yml'da har bir
# xizmat shu image'dan turli `command` bilan ishga tushiriladi.

FROM python:3.12-slim

# Tizim darajasidagi bog'liqliklar:
#   - clamav: scanners/clamav_scanner.py uchun (clamscan CLI)
#   - snmp: response/switch_adapter.py uchun (snmpset CLI)
#   - arp-scan: network_discovery/arp_scanner.py uchun (ARP discovery)
#   - nmap: network_discovery/tcp_scanner.py uchun (port/OS aniqlash)
#   - iputils-ping: network_discovery/icmp_scanner.py uchun (ping sweep)
#   - iproute2: network_discovery/ipv6_discovery.py uchun (`ip -6 neigh` CLI)
#   - build-essential: yara-python kompilyatsiyasi uchun
RUN apt-get update && apt-get install -y --no-install-recommends \
        clamav \
        clamav-freshclam \
        snmp \
        arp-scan \
        nmap \
        iputils-ping \
        iproute2 \
        tzdata \
        build-essential \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary gunicorn

COPY . .

# Loglar va SQLite (agar ishlatilsa) uchun papka
RUN mkdir -p /app/logs

# XAVFSIZLIK (Docker container hardening, BOSQICH 0): standart holatda
# barcha xizmat root sifatida ishlardi. Endi standart, NON-ROOT foydalanuvchi
# (uid/gid 1000 - production host'dagi asosiy foydalanuvchi bilan BIR XIL,
# shuning uchun `./logs` kabi host bind-mount'lar ustidan qo'shimcha
# ruxsat sozlamasisiz to'g'ridan-to'g'ri ishlaydi) - konteyner buzilsa/
# masalan RCE orqali ekspluatatsiya qilinsa ham, host darajasida root
# huquqiga ega bo'lolmaydi.
#
# MUHIM ISTISNO: `network_discovery` xizmati (docker-compose.yml'da
# `user: "0:0"` bilan ANIQ ustidan yozilgan) - u ARP scan/LLDP-CDP capture
# uchun NET_ADMIN/NET_RAW kerak, bu esa amalda root kontekstida ishonchli
# ishlaydi (Linux capability + non-root final UID kombinatsiyasi qo'shimcha
# murakkablik/xavf keltiradi, bu xizmat allaqachon `--profile discovery`
# ortida, standart holatda o'chiq).
RUN groupadd -g 1000 appuser \
    && useradd -u 1000 -g appuser -m -d /home/appuser -s /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app /home/appuser

ENV HOME=/home/appuser
USER appuser

# Ishlatilmaydigan default CMD - docker-compose.yml har bir xizmat uchun
# aniq `command` beradi (masalan: python -m engine.parser_engine --loop)
CMD ["python", "-m", "collectors.syslog_server"]
