# Електронний деканат — information-security-practice

Навчальний API (FastAPI + SQLite + Alembic + Docker) для практичних робіт з «Безпеки інформаційних систем»:
ЗПР-1 — RBAC, bcrypt, JWT, Security Headers, CORS, Rate Limiting; ЗПР-2 — шифрування PII, журнал аудиту, hardening, аудит безпеки.

## Запуск з чистого клону

Команди виконуються в Git Bash / WSL, Docker Desktop має бути запущений.

```bash
cp .env.example .env
openssl rand -hex 32                      # -> JWT_SECRET_KEY у .env
docker compose build api
docker run --rm information-security-practice-api python -m scripts.generate_key  # -> ENCRYPTION_KEY, BLIND_INDEX_KEY у .env
./scripts/generate_cert.sh                # self-signed сертифікат для Nginx
docker compose up -d --build
docker compose exec api alembic upgrade head
docker compose exec api python -m app.seed
```

API: `https://localhost` (Nginx, HTTP 80 → 301 на HTTPS), напряму — лише `http://127.0.0.1:8000`.
Swagger: `https://localhost/docs`. Тестові користувачі: `admin / Admin123!@#`, `teacher01 / Teacher123!`, `student01 / Student123!`.

### Оновлення бази з ЗПР-1 (з наявними даними)

```bash
docker compose down
docker run --rm -v information-security-practice_db_data:/data alpine chown -R 1000:1000 /data
docker compose up -d --build
docker compose exec api python -m scripts.backup_db       # зашифрований бекап перед міграцією
docker compose exec api alembic upgrade +1                # нові колонки encrypted_email, email_index, encrypted_phone
docker compose exec api python -m scripts.migrate_encrypt # шифрування наявних email
docker compose exec api alembic upgrade head              # видалення відкритого email, таблиця audit_log
```

### Якщо антивірус перевіряє HTTPS (Avast, Kaspersky, корпоративний проксі)

Збірка падає з `CERTIFICATE_VERIFY_FAILED`, бо контейнер не знає кореневого сертифіката антивірусу.
TLS-перевірку **не вимикаємо**: відкриту частину вже довіреного в Windows сертифіката експортуємо в `.local-ca/` (каталог у `.gitignore`) і передаємо лише на час `pip install`:

```bash
DOCKER_BUILDKIT=1 docker build --secret id=extra_ca,src=.local-ca/avast-root.pem -t information-security-practice-api .
docker compose up -d
EXTRA_CA_DIR=.local-ca ./scripts/security_check.sh
```

## Безпека

| Захід | Де |
|---|---|
| Паролі — bcrypt; JWT access/refresh (PyJWT, HS256) | `app/security.py`, `app/auth/` |
| RBAC admin / teacher / student | `app/auth/dependencies.py` |
| Шифрування email/phone (Fernet), сліпий індекс HMAC-SHA256, ротація ключа (MultiFernet) | `app/crypto/`, `scripts/rotate_keys.py` |
| Зашифрований бекап і перевірка відновлення | `scripts/backup_db.py`, `scripts/restore_db.py` |
| Журнал аудиту 5W, виявлення Brute Force і входів 00:00–06:00 | `app/audit/` |
| Адмін-API: `GET /admin/audit-log` (фільтри, пагінація), `GET /admin/security-stats` | `app/audit/router.py` |
| Контейнер: non-root, read-only, `cap_drop: ALL`, `no-new-privileges`, HEALTHCHECK | `Dockerfile`, `docker-compose.yml` |
| HTTPS через Nginx, редирект 80→443, API лише на 127.0.0.1 | `nginx/nginx.conf` |
| Секрети лише в `.env` (не в Git), без fallback-значень | `.env.example`, `app/config.py` |

Перевірки:

```bash
./scripts/security_check.sh | tee reports/security_check.txt   # очікувано: SECURITY CHECK PASSED
./scripts/pentest_mini.sh | tee reports/pentest_mini.md          # 12 мінітестів через Nginx
```

Після тесту Brute Force вхід з вашої IP блокується на 5 хвилин — перед `pentest_mini.sh` зачекайте.

Звіт аудиту: [SECURITY_AUDIT.md](SECURITY_AUDIT.md), звіти сканерів — у `reports/`.

Ротація ключа шифрування: старий ключ → `ENCRYPTION_KEY_OLD`, новий → `ENCRYPTION_KEY` у `.env`,
`docker compose up -d`, `docker compose exec api python -m scripts.rotate_keys`, потім прибрати `ENCRYPTION_KEY_OLD`.
