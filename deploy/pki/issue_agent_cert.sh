#!/bin/bash
# Bitta Agent (kompyuter) uchun mTLS client sertifikati chiqaradi -
# ichki CA (generate_ca.sh) tomonidan imzolanadi. FAQAT AGENT_MTLS_
# REQUIRED=true bo'lganda kerak (docs_TLS_SETUP.md'ga qarang) - standart
# holatda Agent autentifikatsiyasi mavjud per-agent API token orqali
# ishlaydi, bu skript ixtiyoriy qo'shimcha qatlam.
#
# Ishlatish:
#   bash deploy/pki/issue_agent_cert.sh <hostname>
#
# Natija: deploy/pki/certs/agents/<hostname>.crt + .key (Agent
# kompyuteriga xavfsiz nusxalanadi, masalan GPO orqali SYSVOL'dan).
set -euo pipefail

if [ $# -ne 1 ]; then
    echo "Ishlatish: $0 <agent-hostname>" >&2
    exit 1
fi

HOSTNAME_ARG="$1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="${TLS_CERT_DIR:-$SCRIPT_DIR/certs}"
AGENT_DIR="$CERT_DIR/agents"
CLIENT_DAYS="${TLS_CLIENT_DAYS:-397}"  # ~13 oy - Agent qayta-enroll bo'lishi kerak

if [ ! -f "$CERT_DIR/ca.key" ] || [ ! -f "$CERT_DIR/ca.crt" ]; then
    echo "XATOLIK: Root CA topilmadi ($CERT_DIR/ca.crt) - avval generate_ca.sh'ni ishga tushiring" >&2
    exit 1
fi

mkdir -p "$AGENT_DIR"
cd "$AGENT_DIR"

log() { echo "[issue_agent_cert] $1"; }

log "'$HOSTNAME_ARG' uchun client sertifikat chiqarilmoqda..."

CONF_FILE="$(mktemp)"
trap 'rm -f "$CONF_FILE"' EXIT
printf '[req]\ndistinguished_name=req_distinguished_name\nreq_extensions=v3_req\nprompt=no\n[req_distinguished_name]\nCN=%s\nO=Network Security System Agent\n[v3_req]\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' \
    "$HOSTNAME_ARG" > "$CONF_FILE"

openssl genrsa -out "${HOSTNAME_ARG}.key" 2048 2>/dev/null
chmod 600 "${HOSTNAME_ARG}.key"
openssl req -new -key "${HOSTNAME_ARG}.key" -out "${HOSTNAME_ARG}.csr" -config "$CONF_FILE" 2>/dev/null
openssl x509 -req -in "${HOSTNAME_ARG}.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" -CAcreateserial \
    -out "${HOSTNAME_ARG}.crt" -days "$CLIENT_DAYS" -sha256 \
    -extfile "$CONF_FILE" -extensions v3_req 2>/dev/null
rm -f "${HOSTNAME_ARG}.csr"

log "Tayyor: $AGENT_DIR/${HOSTNAME_ARG}.crt (+ .key)"
openssl verify -CAfile "$CERT_DIR/ca.crt" "${HOSTNAME_ARG}.crt"
