#!/bin/sh
# nginx TLS reverse proxy uchun entrypoint - shablonni (nginx.conf.template)
# muhit o'zgaruvchilari bilan to'ldiradi, keyin haqiqiy nginx'ni ishga
# tushiradi. docker-compose.yml'dagi `nginx` xizmatida ishlatiladi.
#
# MUHIM: `sed -c` ko'p qatorli almashtirish sintaksisi turli sed
# implementatsiyalari (GNU vs BusyBox/Alpine) orasida farq qilishi
# mumkinligi sababli, ataylab shu yerda PORTATIV `awk` ishlatiladi -
# ikkalasida ham bir xil ishlaydi (real test: run_full_test.py).
set -eu

: "${NGINX_AGENT_API_PORT:=8443}"
: "${NGINX_DASHBOARD_PORT:=8843}"
: "${NGINX_TLS_CERT_FILE:=/etc/nginx/tls/server.crt}"
: "${NGINX_TLS_KEY_FILE:=/etc/nginx/tls/server.key}"
: "${AGENT_MTLS_REQUIRED:=false}"
: "${NGINX_TLS_CA_FILE:=/etc/nginx/tls/ca.crt}"
# Backend manzillari - Docker Compose'da xizmat nomlari (standart),
# lekin run_full_test.py real (docker'siz) sandbox testida bularni
# 127.0.0.1:<port>ga almashtiradi - shu bir xil skript ikkala muhitda
# ham ISHLATILADI (nusxa/soxta konfiguratsiya emas).
: "${NGINX_AGENT_API_UPSTREAM:=agent_api:8443}"
: "${NGINX_DASHBOARD_UPSTREAM:=dashboard:8080}"
: "${NGINX_ERROR_LOG:=/var/log/nginx/error.log}"
: "${NGINX_ACCESS_LOG:=/var/log/nginx/access.log}"
: "${NGINX_PID_FILE:=/tmp/nginx.pid}"

TEMPLATE="${NGINX_TEMPLATE_FILE:-/etc/nginx/nginx.conf.template}"
OUT="${NGINX_OUT_FILE:-/etc/nginx/nginx.conf}"

export NGINX_AGENT_API_PORT NGINX_DASHBOARD_PORT NGINX_TLS_CERT_FILE NGINX_TLS_KEY_FILE
export NGINX_AGENT_API_UPSTREAM NGINX_DASHBOARD_UPSTREAM
export NGINX_ERROR_LOG NGINX_ACCESS_LOG NGINX_PID_FILE
envsubst '${NGINX_AGENT_API_PORT} ${NGINX_DASHBOARD_PORT} ${NGINX_TLS_CERT_FILE} ${NGINX_TLS_KEY_FILE} ${NGINX_AGENT_API_UPSTREAM} ${NGINX_DASHBOARD_UPSTREAM} ${NGINX_ERROR_LOG} ${NGINX_ACCESS_LOG} ${NGINX_PID_FILE}' \
    < "$TEMPLATE" > "$OUT.tmp"

if [ "$AGENT_MTLS_REQUIRED" = "true" ]; then
    echo "[entrypoint] AGENT_MTLS_REQUIRED=true - Agent API uchun mTLS (client sertifikat) MAJBURIY qilinmoqda"
else
    echo "[entrypoint] AGENT_MTLS_REQUIRED=false (standart) - faqat server-tomon TLS, mTLS o'chirilgan"
fi

MTLS_REQUIRED="$AGENT_MTLS_REQUIRED" NGINX_TLS_CA_FILE="$NGINX_TLS_CA_FILE" awk '
    /__MTLS_BLOCK__/ {
        if (ENVIRON["MTLS_REQUIRED"] == "true") {
            print "        ssl_client_certificate " ENVIRON["NGINX_TLS_CA_FILE"] ";"
            print "        ssl_verify_client on;"
        }
        next
    }
    /__MTLS_HEADER__/ {
        if (ENVIRON["MTLS_REQUIRED"] == "true") {
            print "            proxy_set_header X-Client-Cert-Verified $ssl_client_verify;"
            print "            proxy_set_header X-Client-Cert-CN $ssl_client_s_dn;"
        }
        next
    }
    { print }
' "$OUT.tmp" > "$OUT"
rm -f "$OUT.tmp"

nginx -t -c "$OUT"
exec nginx -g "daemon off;" -c "$OUT"
