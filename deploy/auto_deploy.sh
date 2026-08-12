#!/bin/bash
# Avtomatik Deploy skripti - yangi TZ (CI/CD) bo'limi.
#
# GitHub'dagi (SSH orqali klonlangan) repo'ni davriy tekshiradi -
# yangi commit topilsa: backup oladi -> pull qiladi -> Docker
# image'larni qayta quradi -> xizmatlarni qayta ishga tushiradi ->
# health-check qiladi. O'zgarish bo'lmasa, hech narsa qilmaydi.
#
# systemd timer orqali har necha daqiqada ishga tushiriladi
# (docs_DEPLOYMENT_SSH_AUTOUPDATE.md'ga qarang).
#
# Qo'lda ishga tushirish:
#   REPO_DIR=/opt/network_security_system bash deploy/auto_deploy.sh
set -euo pipefail

REPO_DIR="${REPO_DIR:-/opt/network_security_system}"
BRANCH="${DEPLOY_BRANCH:-main}"
LOG_FILE="${DEPLOY_LOG_FILE:-/var/log/network_security_deploy.log}"
LOCK_FILE="${DEPLOY_LOCK_FILE:-/tmp/network_security_deploy.lock}"
HEALTH_CHECK_URL="${DEPLOY_HEALTH_CHECK_URL:-http://localhost:8080/login}"
DOCKER_COMPOSE_CMD="${DOCKER_COMPOSE_CMD:-docker compose}"

log() {
    echo "$(date -Iseconds) [auto_deploy] $1" | tee -a "$LOG_FILE"
}

# --- Bir vaqtda bir nechta deploy jarayoni ishga tushib qolmasligi uchun (flock) ---
exec 200>"$LOCK_FILE"
if ! flock -n 200; then
    log "Boshqa deploy jarayoni allaqachon ishlamoqda - chiqilmoqda"
    exit 0
fi

if [ ! -d "$REPO_DIR/.git" ]; then
    log "XATOLIK: $REPO_DIR git repo emas. Avval SSH orqali klonlang (docs_DEPLOYMENT_SSH_AUTOUPDATE.md)"
    exit 1
fi

cd "$REPO_DIR"

git fetch origin "$BRANCH" --quiet

LOCAL_COMMIT=$(git rev-parse HEAD)
REMOTE_COMMIT=$(git rev-parse "origin/$BRANCH")

if [ "$LOCAL_COMMIT" = "$REMOTE_COMMIT" ]; then
    # O'zgarish yo'q - jim chiqamiz (log'ni har 5 daqiqada "o'zgarish yo'q"
    # bilan to'ldirmaslik uchun, faqat DEBUG rejimida yozamiz)
    if [ "${DEPLOY_VERBOSE:-0}" = "1" ]; then
        log "O'zgarish yo'q (HEAD=$LOCAL_COMMIT)"
    fi
    exit 0
fi

log "Yangi commit topildi: ${LOCAL_COMMIT:0:7} -> ${REMOTE_COMMIT:0:7}. Deploy boshlanmoqda..."

# --- 1) Xavfsizlik: deploy'dan OLDIN backup ---
if command -v python3 >/dev/null 2>&1; then
    log "Backup olinmoqda (deploy'dan oldin)..."
    python3 -m backup.backup_manager --backup >> "$LOG_FILE" 2>&1 || \
        log "OGOHLANTIRISH: backup muvaffaqiyatsiz - shunga qaramay davom etilmoqda"
fi

# --- 2) Kod yangilanishi ---
git pull origin "$BRANCH" --quiet
log "Kod yangilandi: $(git rev-parse HEAD)"

# --- 3) Docker image'larni qayta qurish va xizmatlarni yangilash ---
$DOCKER_COMPOSE_CMD build >> "$LOG_FILE" 2>&1
$DOCKER_COMPOSE_CMD up -d --remove-orphans >> "$LOG_FILE" 2>&1

# --- 4) Health-check (deploy haqiqatan muvaffaqiyatli bo'lganini tasdiqlash) ---
log "Health-check kutilmoqda..."
sleep 10
HEALTH_OK=0
for _ in 1 2 3; do
    if curl -sf "$HEALTH_CHECK_URL" > /dev/null 2>&1; then
        HEALTH_OK=1
        break
    fi
    sleep 5
done

if [ "$HEALTH_OK" -eq 1 ]; then
    log "✅ Deploy muvaffaqiyatli yakunlandi: $(git rev-parse HEAD)"
else
    log "❌ XATOLIK: deploy'dan keyin health-check muvaffaqiyatsiz ($HEALTH_CHECK_URL javob bermayapti)!"
    log "   Qo'lda tekshiring: docker compose logs -f"
    exit 1
fi
