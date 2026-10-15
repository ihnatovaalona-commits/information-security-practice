#!/usr/bin/env bash
# scripts/security_check.sh — автоматична перевірка конфігурації/залежностей. Exit 1 = є FAIL.
set -u
cd "$(dirname "$0")/.."
# Git Bash (Windows) не повинен перетворювати шляхи в аргументах docker
export MSYS_NO_PATHCONV=1
SRC="$(pwd -W 2>/dev/null || pwd)"
IMAGE="${IMAGE:-information-security-practice-api}"
FAIL=0; WARN=0
ok()   { echo "  [OK]   $1"; }
warn() { echo "  [WARN] $1"; WARN=$((WARN+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
mkdir -p reports

# Необов'язково: каталог з додатковим кореневим CA (напр. антивірус з HTTPS-скануванням).
# TLS-перевірка лишається увімкненою: CA лише додається до стандартних.
CA_MOUNT=""; CA_PY=""; CA_GO=""
if [ -n "${EXTRA_CA_DIR:-}" ] && [ -d "$EXTRA_CA_DIR" ]; then
    CA_MOUNT="-v $(cd "$EXTRA_CA_DIR" && pwd -W 2>/dev/null || pwd):/extra-ca:ro"
    CA_PY="cat /etc/ssl/certs/ca-certificates.crt /extra-ca/*.pem > /tmp/ca.pem && \
export PIP_CERT=/tmp/ca.pem REQUESTS_CA_BUNDLE=/tmp/ca.pem SSL_CERT_FILE=/tmp/ca.pem && "
    CA_GO="-e SSL_CERT_DIR=/etc/ssl/certs:/extra-ca"
fi

echo "== 1. Секрети =="
grep -qxE '\.env' .gitignore 2>/dev/null && ok ".env у .gitignore" || fail ".env не в .gitignore"
git ls-files --error-unmatch .env >/dev/null 2>&1 && fail ".env у Git!" || ok ".env не в Git"
if git log --all -p 2>/dev/null    | grep -E '^\+.*(ENCRYPTION_KEY|BLIND_INDEX_KEY|JWT_SECRET_KEY)=[A-Za-z0-9_=-]{20,}'    | grep -qviE '=(replace-me|change-me|your-|example)'; then
    fail "Секрети в історії Git — ротуйте ключі!"
else ok "Секретів в історії Git немає"; fi
if grep -rnE 'getenv\("[A-Z_]*(SECRET|KEY|PASSWORD)[A-Z_]*", *"[^"]{8,}"' app/ --include='*.py'; then
    fail "fallback-секрет у getenv (див. вище)"
else ok "fallback-секретів у коді немає"; fi
grep -q ':-dev' docker-compose.yml && fail "docker-compose.yml: dev-секрет за замовчуванням" \
    || ok "docker-compose.yml без dev-секретів"

echo "== 2. Docker =="
grep -qE '^USER\s+\S+' Dockerfile && ok "Dockerfile: USER (non-root)" || fail "Dockerfile без USER"
grep -q '^HEALTHCHECK' Dockerfile && ok "Dockerfile: HEALTHCHECK" || warn "Немає HEALTHCHECK"
grep -qE '^CMD.*--reload' Dockerfile && warn "Dockerfile: --reload (лише для розробки)" || ok "Без --reload"
grep -q 'read_only: true' docker-compose.yml && ok "compose: read_only" || warn "compose: без read_only"
grep -q 'no-new-privileges' docker-compose.yml && ok "compose: no-new-privileges" || warn "compose: без no-new-privileges"
CID=$(docker compose ps -q api 2>/dev/null)
if [ -n "$CID" ]; then
    WHO=$(docker compose exec -T api whoami 2>/dev/null | tr -d '\r')
    [ -n "$WHO" ] && [ "$WHO" != "root" ] && ok "Контейнер працює як '$WHO'" || fail "Контейнер працює як root"
    H=$(docker inspect --format='{{.State.Health.Status}}' "$CID")
    [ "$H" = "healthy" ] && ok "healthcheck: healthy" || warn "healthcheck: $H"
else warn "api не запущено — runtime-перевірки пропущено"; fi

echo "== 3. HTTPS і заголовки =="
HDR=$(curl -sk -D - -o /dev/null https://localhost/health 2>/dev/null)
if [ -n "$HDR" ]; then
    for h in Strict-Transport-Security Content-Security-Policy X-Frame-Options X-Content-Type-Options; do
        echo "$HDR" | grep -qi "^$h:" && ok "Заголовок $h" || fail "Немає заголовка $h"
    done
    echo "$HDR" | grep -qi '^server: nginx/' && warn "Nginx розкриває версію" || ok "Версія сервера прихована"
    CODE=$(curl -s -o /dev/null -w '%{http_code}' http://localhost/)
    [ "$CODE" = "301" ] && ok "HTTP -> HTTPS (301)" || warn "HTTP повертає $CODE"
else warn "https://localhost недоступний"; fi

echo "== 4. Залежності, код, образ =="
if docker info >/dev/null 2>&1; then
    docker run --rm $CA_MOUNT -v "$SRC":/src -w /src python:3.11-slim sh -c \
        "${CA_PY}pip install -q pip-audit >/dev/null 2>&1 && pip-audit -r requirements.txt" > reports/pip-audit.txt 2>&1 \
        && ok "pip-audit: вразливостей не знайдено" || warn "pip-audit: є знахідки (reports/pip-audit.txt)"
    docker run --rm $CA_MOUNT -v "$SRC":/src -w /src python:3.11-slim sh -c \
        "${CA_PY}pip install -q bandit >/dev/null 2>&1 && bandit -r app -lll -q" > reports/bandit-high.txt 2>&1 \
        && ok "Bandit: HIGH-знахідок немає" || fail "Bandit: є HIGH (reports/bandit-high.txt)"
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        docker run --rm $CA_MOUNT $CA_GO -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.56.2 image -q \
            --severity CRITICAL --ignore-unfixed --exit-code 1 "$IMAGE" > reports/trivy-critical.txt 2>&1 \
            && ok "Trivy: CRITICAL з виправленням немає" || warn "Trivy: є CRITICAL (reports/trivy-critical.txt)"
    else warn "Образ $IMAGE не знайдено (docker compose build)"; fi
else warn "Docker daemon недоступний — сканування пропущено"; fi

echo "=================================="
echo "FAIL: $FAIL  WARN: $WARN"
[ "$FAIL" -eq 0 ] && echo "SECURITY CHECK PASSED" || echo "SECURITY CHECK FAILED"
exit $(( FAIL > 0 ))
