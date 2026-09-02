#!/bin/bash
# Ichki (o'z-o'zidan tasdiqlaydigan) Certificate Authority + server
# sertifikatini yaratadi - Agent API (8443) va Dashboard (8843) uchun
# nginx TLS termination'da ishlatiladi (deploy/nginx/nginx.conf.template).
#
# XAVFSIZLIK: bu ICHKI, korporativ tarmoq uchun CA - jamoat internet
# brauzerlari uni tanimaydi (aynan shu maqsad uchun - tashqi CA'ga
# muhtoj emas). Har bir Windows/Linux/Mac Agent va Dashboard
# foydalanuvchisi (brauzer) shu `ca.crt`ni o'z ishonchli sertifikatlar
# do'koniga (yoki Agent uchun `AGENT_CA_BUNDLE_FILE` orqali to'g'ridan-
# to'g'ri) qo'shishi kerak - docs_TLS_SETUP.md'ga qarang.
#
# Idempotent: agar CA allaqachon mavjud bo'lsa, uni QAYTA YARATMAYDI
# (aks holda barcha allaqachon tarqatilgan Agent'lar ishonchini
# yo'qotib qo'yardi) - faqat server sertifikatini (odatda qisqaroq
# muddatli) SANlar o'zgargan yoki muddati o'tgan bo'lsa yangilaydi.
#
# Ishlatish:
#   TLS_SERVER_HOSTNAMES="security-agent-api.company.local,dashboard.company.local" \
#   TLS_SERVER_IPS="172.16.1.206" \
#   bash deploy/pki/generate_ca.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${TLS_CERT_DIR:-$SCRIPT_DIR/certs}"
CA_DAYS="${TLS_CA_DAYS:-3650}"        # 10 yil - CA uzoq muddatli bo'lishi kerak
SERVER_DAYS="${TLS_SERVER_DAYS:-825}" # ~27 oy (CA/Browser forum'ning maksimal server sertifikat muddatiga mos)
TLS_SERVER_HOSTNAMES="${TLS_SERVER_HOSTNAMES:-security-agent-api.company.local,dashboard.company.local,localhost}"
TLS_SERVER_IPS="${TLS_SERVER_IPS:-127.0.0.1}"

mkdir -p "$CERT_DIR"
cd "$CERT_DIR"

log() { echo "[generate_ca] $1"; }

# --- 1) Root CA (faqat mavjud bo'lmasa yaratiladi) ---
if [ -f "ca.key" ] && [ -f "ca.crt" ]; then
    log "Root CA allaqachon mavjud ($CERT_DIR/ca.crt) - qayta yaratilmaydi"
else
    log "Yangi ichki Root CA yaratilmoqda ($CA_DAYS kun muddat)..."
    openssl genrsa -out ca.key 4096 2>/dev/null
    chmod 600 ca.key
    openssl req -x509 -new -nodes -key ca.key -sha256 -days "$CA_DAYS" \
        -out ca.crt \
        -subj "/C=UZ/O=Network Security System/OU=Internal CA/CN=NetworkSecuritySystem Root CA"
    log "Root CA tayyor: $CERT_DIR/ca.crt (bu faylni Agent/brauzerlarga tarqating)"
fi

# --- 2) Server sertifikati (SAN'lar bilan) - har chaqirilganda YANGILANADI ---
# (server sertifikati qisqa muddatli va SAN ro'yxati (hostname/IP)
# tez-tez o'zgarishi mumkin bo'lgani uchun bu qadam idempotent EMAS -
# doim eng so'nggi TLS_SERVER_HOSTNAMES/TLS_SERVER_IPS'dan qayta quriladi)
log "Server sertifikati qurilmoqda - SAN: hostnames=[$TLS_SERVER_HOSTNAMES] ips=[$TLS_SERVER_IPS]"

SAN_ENTRIES=""
IFS=',' read -ra HOSTS <<< "$TLS_SERVER_HOSTNAMES"
i=1
for h in "${HOSTS[@]}"; do
    h_trimmed="$(echo "$h" | xargs)"
    [ -z "$h_trimmed" ] && continue
    SAN_ENTRIES="${SAN_ENTRIES}DNS.${i}=${h_trimmed}\n"
    i=$((i+1))
done
IFS=',' read -ra IPS <<< "$TLS_SERVER_IPS"
j=1
for ip in "${IPS[@]}"; do
    ip_trimmed="$(echo "$ip" | xargs)"
    [ -z "$ip_trimmed" ] && continue
    SAN_ENTRIES="${SAN_ENTRIES}IP.${j}=${ip_trimmed}\n"
    j=$((j+1))
done

OPENSSL_CONF_FILE="$(mktemp)"
trap 'rm -f "$OPENSSL_CONF_FILE"' EXIT
printf '[req]\ndistinguished_name=req_distinguished_name\nreq_extensions=v3_req\nprompt=no\n[req_distinguished_name]\nCN=%s\nO=Network Security System\n[v3_req]\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=@alt_names\n[alt_names]\n%b' \
    "${HOSTS[0]:-security-agent-api.company.local}" "$SAN_ENTRIES" > "$OPENSSL_CONF_FILE"

openssl genrsa -out server.key 2048 2>/dev/null
chmod 600 server.key
openssl req -new -key server.key -out server.csr -config "$OPENSSL_CONF_FILE" 2>/dev/null
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out server.crt -days "$SERVER_DAYS" -sha256 \
    -extfile "$OPENSSL_CONF_FILE" -extensions v3_req 2>/dev/null
rm -f server.csr

log "Server sertifikati tayyor: $CERT_DIR/server.crt (+ server.key)"
log "Tekshirish: openssl verify -CAfile ca.crt server.crt"
openssl verify -CAfile ca.crt server.crt
