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

# Ishlatilmaydigan default CMD - docker-compose.yml har bir xizmat uchun
# aniq `command` beradi (masalan: python -m engine.parser_engine --loop)
CMD ["python", "-m", "collectors.syslog_server"]
