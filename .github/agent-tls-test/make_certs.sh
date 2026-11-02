#!/usr/bin/env bash
# CI (windows-latest, Git bash openssl): AgentTls.ps1 testi uchun sertifikatlar.
#   ca_a  - agent ishonadigan CA (paketdagi agent-ca.crt o'rnida)
#   ca_b  - begona CA
#   good       : ca_a imzolagan, SAN=127.0.0.1           -> qabul qilinishi kerak
#   wrong_ca   : ca_b imzolagan, SAN=127.0.0.1           -> rad etilishi kerak
#   wrong_name : ca_a imzolagan, SAN=other.example faqat -> rad etilishi kerak
set -euo pipefail
out="${1:?out dir}"
mkdir -p "$out"
cd "$out"

ca() {
    openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.crt" -days 2 \
        -subj "/CN=$1 test CA" -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
}
leaf() {  # name ca san
    printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > "$1.ext"
    openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
    openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.key" -CAcreateserial -out "$1.crt" -days 2 \
        -sha256 -extfile "$1.ext" 2>/dev/null
}
ca ca_a
ca ca_b
leaf good ca_a "IP:127.0.0.1"
leaf wrong_ca ca_b "IP:127.0.0.1"
leaf wrong_name ca_a "DNS:other.example"
ls -1 "$out"
