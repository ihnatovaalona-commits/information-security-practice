# Звіт аудиту безпеки — «Електронний деканат»

| Поле | Значення |
|---|---|
| Аудитор | ihnatovaalona-commits, ЗПР-2 «Безпека інформаційних систем» |
| Дата аудиту | 2026-10-15 |
| Версія системи | commit `fdba265` (ЗПР-2, stage4; база ЗПР-1 — `f66f8c3`) |
| Обсяг (scope) | API FastAPI, база SQLite, Docker-конфігурація, Nginx, залежності |
| Поза обсягом | інфраструктура хостингу, соціальна інженерія, фізичний доступ (лише в моделі загроз) |
| Методи | STRIDE, OWASP Top 10 (2021), Trivy 0.56.2, pip-audit, Bandit, `security_check.sh`, `pentest_mini.sh` |

## 1. Резюме для керівництва

Система після ЗПР-2 має багаторівневий захист: персональні дані (email, телефон) у БД зашифровані Fernet, бекап шифрується, усі безпекові події пишуться в журнал 5W, атаки підбору пароля зупиняються двома незалежними механізмами, контейнер працює без root у read-only режимі за HTTPS.
Усі 12 мінітестів пройдені, `security_check.sh` — **PASSED (FAIL 0, WARN 0)**, pip-audit — 0 вразливостей, Bandit — 0 знахідок, Trivy — 0 CRITICAL.
Найвищий залишковий ризик — **втрата ключа шифрування** (ключ лише в `.env` одного хоста), далі — крадіжка JWT / фішинг викладача (немає MFA) і блокування легітимних користувачів детектором Brute Force. Перші заходи — резервна копія ключів і MFA для викладачів та адміністраторів.

| Критичних | Високих | Середніх | Низьких |
|---|---|---|---|
| 0 | 1 | 8 | 3 |

(Залишкові ризики з матриці розділу 5; усі знахідки High з розділу 6 виправлені й перевірені повторно.)

## 2. Активи системи

| Актив | Цінність | Власник | Що станеться при компрометації |
|---|---|---|---|
| `data/app.db` (volume `db_data`) | Висока | Адміністратор | Витік ПІБ, email, оцінок; підміна оцінок |
| `ENCRYPTION_KEY`, `BLIND_INDEX_KEY`, `JWT_SECRET_KEY` (`.env`) | Критична | Адміністратор | Втрата = втрата PII; витік = підробка токенів / розшифрування PII |
| `data/backups/*.db.enc` | Висока | Адміністратор | Без ключа марні; з ключем — повна копія БД |
| `audit_log` | Висока | Адміністратор / аудитор | Втрата доказів інцидентів (Repudiation) |
| Облікові записи admin / teacher | Висока | Користувачі | Зміна оцінок, перегляд журналу й PII |
| TLS-ключ `nginx/certs/selfsigned.key` | Середня | Адміністратор | MITM (сертифікат self-signed, лише для стенда) |

## 3. Реалізовані заходи (Defense in Depth)

| Рівень | Заходи | Де (ЗПР / файли) |
|---|---|---|
| Автентифікація | bcrypt, JWT access (30 хв) + refresh (7 днів), HS256 з `algorithms=[...]` (PyJWT) | ЗПР-1/2, `app/security.py`, `app/auth/` |
| Авторизація | RBAC admin/teacher/student (перевірка на сервері) | ЗПР-1, `app/auth/dependencies.py` |
| Вхідні дані / веб | Pydantic, bleach, CSP, HSTS, CORS без `*`, slowapi (login 5/хв) | ЗПР-1, `app/middleware/`, `app/schemas.py` |
| Шифрування даних | Fernet для email/phone, сліпий індекс HMAC-SHA256, MultiFernet + ротація, зашифрований бекап | ЗПР-2, `app/crypto/`, `scripts/` |
| Аудит і виявлення | `audit_log` 5W, AuditMiddleware (401/403/429/5xx), Brute Force, off-hours, `/admin/audit-log`, `/admin/security-stats`, JSON-логи без секретів | ЗПР-2, `app/audit/` |
| Середовище | multi-stage, non-root `appuser` (UID 1000), `read_only`, `tmpfs /tmp`, `cap_drop: ALL`, `no-new-privileges`, HEALTHCHECK, API лише на 127.0.0.1, Nginx HTTPS (TLS 1.2+), 80→443, `server_tokens off`, `limit_req` | ЗПР-2, `Dockerfile`, `docker-compose.yml`, `nginx/` |
| Секрети | лише в `.env` (у `.gitignore`), fail-fast без fallback, `${VAR:?}` у compose | ЗПР-2, `app/config.py`, `app/crypto/key_manager.py` |
| DevSecOps | Trivy, pip-audit, Bandit, `security_check.sh`, `pentest_mini.sh` | ЗПР-2, `reports/` |

## 4. Модель загроз STRIDE

| STRIDE | Загроза | Реалізований захід | Залишковий ризик / план |
|---|---|---|---|
| Spoofing | Підбір пароля; підробка або крадіжка JWT | bcrypt; HS256 з фіксованим `algorithms`; перевірка `type` access/refresh; slowapi + детектор Brute Force | Немає MFA; HS256 — один спільний секрет → MFA, у перспективі RS256 |
| Tampering | Зміна оцінок/ролей; підміна шифротексту в БД | RBAC `require_role`; Pydantic; HMAC у Fernet (підміна → `[ПОМИЛКА РОЗШИФРУВАННЯ]`) | Оцінки в БД не підписані; адмін із доступом до файлу БД може змінити їх напряму |
| Repudiation | Викладач заперечує, що змінив оцінку | `grades.assigned_by`; `audit_log` 5W; `data_change` з old/new | Журнал можна змінити з доступом до БД → hash-chain або відправка в зовнішній SIEM |
| Information Disclosure | Витік `app.db` чи бекапу; перехоплення трафіку | Fernet для email/phone; бекап шифрується; HTTPS; секрети поза Git; журнал без паролів/токенів | `full_name` і оцінки не шифруються; ключі на тому ж хості, що й БД |
| Denial of Service | Флуд `/auth/login`; блокування чужого акаунта | slowapi; Nginx `limit_req`; `client_max_body_size 1m` | Детектор блокує за IP **або** username → можна заблокувати жертву на 5 хв; за Docker Desktop усі клієнти хоста мають одну IP |
| Elevation of Privilege | Студент → адмін; втеча з контейнера | Серверний RBAC; non-root; `cap_drop: ALL`; `no-new-privileges`; read-only FS | Немає перевірки IDOR для майбутніх ендпоінтів; немає власного seccomp-профілю |

## 5. Матриця ризиків (залишковий ризик)

Ризик = Ймовірність × Вплив. 1–4 низький, 5–9 середній, 10–15 високий, 16–25 критичний.

| # | Загроза | Ймов. | Вплив | Ризик | Рівень | Обґрунтування |
|---|---|---|---|---|---|---|
| R1 | Brute Force / credential stuffing | 2 | 4 | 8 | Середній | Атака легка, але slowapi (5/хв) і детектор (5 невдач / 5 хв) роблять повний підбір непрактичним; T12 → 429. |
| R2 | SQL Injection | 1 | 5 | 5 | Середній | Усі запити через ORM / `text()` з параметрами, T10 → 401; вплив був би повним витоком БД. |
| R3 | Stored XSS | 1 | 3 | 3 | Низький | Allowlist для `full_name` (T9 → 422), bleach для коментарів, CSP `default-src 'none'`; фронтенду поки немає. |
| R4 | Крадіжка JWT | 3 | 3 | 9 | Середній | Відкликання токенів і прив'язки до клієнта немає, але HTTPS і access TTL 30 хв обмежують вікно використання. |
| R5 | Витік БД або бекапу | 2 | 3 | 6 | Середній | PII і бекап зашифровані; відкриті лишаються ПІБ і оцінки; файл доступний лише з volume. |
| R6 | Втрата `ENCRYPTION_KEY` | 2 | 5 | 10 | Високий | Ключ зберігається лише в `.env` одного хоста; без нього email і всі бекапи невідновні. |
| R7 | Вразлива залежність | 2 | 3 | 6 | Середній | Після оновлення pip-audit = 0, Trivy CRITICAL = 0; лишаються 44 HIGH в ОС-пакетах Debian і 2 в build-інструментах. |
| R8 | Фішинг викладача | 3 | 3 | 9 | Середній | Викладач може змінювати оцінки; MFA немає, але кожна зміна йде в `data_change` з old/new. |
| R9 | DoS через блокування акаунта детектором | 3 | 2 | 6 | Середній | Будь-хто може 5 разів ввести невірний пароль до чужого логіна й заблокувати його на 5 хв. |
| R10 | Підміна записів `audit_log` | 1 | 3 | 3 | Низький | Потрібен доступ до файлу БД у volume; hash-chain не реалізовано. |
| R11 | Компрометація TLS (self-signed) | 2 | 2 | 4 | Низький | Лише для локального стенда; у production — Let's Encrypt. |
| R12 | Витік секретів через Git | 1 | 5 | 5 | Середній | `.env`, сертифікати, `*.db.enc` у `.gitignore`; перевірка історії в `security_check.sh` → OK. |

Найвищий залишковий ризик: **R6 — втрата `ENCRYPTION_KEY` (10, високий)**: ймовірність невисока, але наслідок незворотний. Перший захід — резервна копія ключів у захищеному сховищі (розділ 11, п. 1), далі MFA для R4/R8.

## 6. Знахідки аудиту

| ID | Рівень | Знахідка | Доказ | Рішення | Статус / retest |
|---|---|---|---|---|---|
| F-01 | High | Fallback JWT-секрет у `config.py` і `:-dev-only-secret` у compose | `security_check.sh` на коді ЗПР-1 | Прибрано fallback, fail-fast при довжині < 32, `${VAR:?}` | Виправлено; retest: «fallback-секретів немає», «compose без dev-секретів» — OK |
| F-02 | High (CRITICAL у Trivy) | Вразливі залежності: python-jose 3.3.0 (CVE-2024-33663 CRITICAL, CVE-2024-33664 + 2 без виправлення), ecdsa (CVE-2024-23342, без виправлення), starlette 0.37.2 (через fastapi 0.111.0), python-multipart 0.0.9, bleach 6.1.0 | pip-audit до виправлення: **38 вразливостей у 5 пакетах**; Trivy Python: 14 (2 CRITICAL, 12 HIGH) | fastapi 0.143.2 (starlette 1.8.0), python-multipart 0.0.32, bleach 6.4.0, pydantic 2.14.1; python-jose → **PyJWT 2.15.1** (прибирає ecdsa) | Виправлено; retest: pip-audit «No known vulnerabilities found», Trivy Python CRITICAL 0, `pentest_mini.sh` 12/12 |
| F-03 | High | Контейнер від root, `--reload`, bind-mount коду, API на 0.0.0.0:8000, немає HEALTHCHECK | `Dockerfile` / compose ЗПР-1 | Multi-stage, `USER appuser`, read-only, cap_drop, `127.0.0.1:8000`, Nginx HTTPS | Виправлено; retest: `whoami` → appuser, `touch` → Read-only file system, healthy, LAN-запит на :8000 не відповідає |
| F-04 | High | Email зберігався відкритим текстом | схема `users` ЗПР-1 | Fernet + сліпий індекс, міграції Alembic, `migrate_encrypt.py` (5 записів) | Виправлено; retest: T11 `gAAAA…`, колонки `email` у БД немає |
| F-05 | Info | `security_check.sh` позначив «секрет в історії Git» | commit `1d44203`, `.env.example` | Перевірено вручну: це заглушка `replace-me-with-64-hex-chars`, `.env` в історії відсутній. Правило уточнено (виключення заглушок) — боротьба з Alert Fatigue | Хибне спрацювання; retest — OK |
| F-06 | Low | Скрипт сканування не працював у Git Bash (перетворення шляхів MSYS) | `reports/bandit-high.txt`: «working directory … is invalid» | `MSYS_NO_PATHCONV=1`, шлях через `pwd -W` | Виправлено; retest: Bandit/pip-audit/Trivy виконуються |
| F-07 | Medium | 44 HIGH у пакетах ОС базового образу `python:3.11-slim` (Debian 13.7: util-linux, ncurses, systemd-libs, perl-base, login) та 2 HIGH у build-інструментах (`wheel` CVE-2026-24049, `jaraco.context` CVE-2026-23949) | `reports/trivy.txt` | Більшість без виправлення в Debian; застосунок не викликає ці утиліти. Прийнято як залишковий ризик; план — регулярне оновлення базового образу / distroless | Прийнято (Trivy `--ignore-unfixed` CRITICAL = 0) |
| F-08 | Medium | Детектор Brute Force блокує за username → DoS легітимного користувача; за Docker Desktop усі клієнти хоста видні як `172.18.0.1` | сценарій етапу 2: правильний пароль після атаки → 429 | Задокументовано; план — CAPTCHA / прогресивна затримка замість жорсткого блокування, сповіщення користувача | Відкрито (план покращень) |

## 7. Чеклист OWASP Top 10 (2021)

| ID | Категорія | Статус | Доказ / контрзахід |
|---|---|---|---|
| A01 | Broken Access Control | ✅ Захищено | T5, T6, T7 → 403; T8 адмін → 200; RBAC на сервері |
| A02 | Cryptographic Failures | ✅ Захищено | bcrypt; Fernet для PII (T11); TLS 1.2+; секрети поза Git; підміна шифротексту → `[ПОМИЛКА РОЗШИФРУВАННЯ]` |
| A03 | Injection | ✅ Захищено | ORM / `text()` з параметрами, T10 → 401; Pydantic; bleach; T9 → 422 |
| A04 | Insecure Design | ⚠️ Частково | Модель загроз є; немає м'якого lockout/MFA, блокування може бути використане для DoS (F-08) |
| A05 | Security Misconfiguration | ✅ Захищено | Security Headers (перевірено через HTTPS), CORS без `*` (evil.example → 400), `server_tokens off`, без fallback-секретів |
| A06 | Vulnerable and Outdated Components | ⚠️ Частково | pip-audit 0, Trivy CRITICAL 0 після оновлення; 44 HIGH в ОС-пакетах базового образу (F-07) |
| A07 | Identification and Authentication Failures | ✅ Захищено | rate limit, детектор Brute Force (T12 → 429), `exp`, refresh ≠ access (T4), alg=none (T3) і підроблений payload (T2) → 401 |
| A08 | Software and Data Integrity Failures | ✅ Захищено | HMAC у Fernet, шифрований бекап (чужий ключ → InvalidToken), закріплені версії залежностей |
| A09 | Security Logging and Monitoring Failures | ✅ Захищено | `audit_log` 5W, детектор, `/admin/security-stats`, JSON у stdout без паролів/токенів (перевірено: 0 збігів) |
| A10 | SSRF | N/A | API не завантажує ресурси за URL користувача |

## 8. Результати сканування

| Інструмент | Тип | CRITICAL | HIGH | MEDIUM | Рішення |
|---|---|---|---|---|---|
| Trivy (образ) | Container SCA | 0 (до оновлення: 2) | 48 = 44 ОС + 4 записи Python (`wheel`, `jaraco.context`) (до: 44 ОС + 12 Python) | — (сканувались HIGH,CRITICAL) | Python-залежності оновлено; ОС-пакети прийнято (F-07) |
| pip-audit | Python SCA | — | 0 (до: 38 у 5 пакетах, 3 з них без виправлення) | — | Оновлення + заміна python-jose на PyJWT (F-02) |
| Bandit | SAST | — | 0 | 0 (Low 0) | Знахідок немає, `# nosec` не використовувався |
| security_check.sh | Конфігурація | FAIL: 0 | WARN: 0 | | SECURITY CHECK PASSED (`reports/security_check.txt`) |

Звіти: `reports/trivy.txt`, `reports/pip-audit.txt`, `reports/bandit.txt`, `reports/security_check.txt`, `reports/pentest_mini.md`.

Примітка щодо середовища: на ПК аудитора Avast перевіряє HTTPS і підставляє власний кореневий сертифікат. Для збірки й сканування цей сертифікат (лише відкрита частина, довірена в Windows) передається як BuildKit secret / змінна `EXTRA_CA_DIR`; перевірка TLS не вимикалась, у фінальний образ і в Git сертифікат не потрапляє.

## 9. Мінітести

Прогін через Nginx (`https://localhost`) після оновлення залежностей:

| Тест | Отримано | Очікувано | Результат |
|---|---|---|---|
| T1 Без токена (/auth/me) | 401 | 401 | ✅ захищено |
| T2 JWT зі зміненим payload | 401 | 401 | ✅ захищено |
| T3 JWT з alg=none | 401 | 401 | ✅ захищено |
| T4 Refresh token замість access | 401 | 401 | ✅ захищено |
| T5 Студент -> /admin/users | 403 | 403 | ✅ захищено |
| T6 Студент -> /admin/audit-log | 403 | 403 | ✅ захищено |
| T7 Студент -> чужі оцінки /teachers | 403 | 403 | ✅ захищено |
| T8 Адмін -> /admin/audit-log | 200 | 200 | ✅ захищено |
| T9 XSS у full_name при реєстрації | 422 | 422 | ✅ захищено |
| T10 SQLi у логіні (' OR '1'='1) | 401 | 401 422 429 | ✅ захищено |
| T11 Email у БД зашифровано | gAAAA | gAAAA | ✅ захищено |
| T12 Brute Force (8 спроб) | 429 | 429 | ✅ захищено |

**Ручна перевірка (CORS):** preflight `OPTIONS /auth/login` з `Origin: https://evil.example` → `400 Bad Request` без `Access-Control-Allow-Origin`; з `Origin: https://localhost` → `200` і `Access-Control-Allow-Origin: https://localhost`. ✅

**Додаткові перевірки етапу 1:** підміна 1 символу `encrypted_email` → `[ПОМИЛКА РОЗШИФРУВАННЯ]`; повторна реєстрація `Student@University.edu` → 409 (сліпий індекс нечутливий до регістру).

## 10. Моніторинг і KPI

| Показник | Значення | Джерело |
|---|---|---|
| Подій за 24 год | 59 (failed_logins 10, access_denied 4, brute_force_alerts 2, off_hours 0, data_changes 1, server_errors 0) | `/admin/security-stats?hours=24` |
| Brute Force виявлено | 2 записи `brute_force_detected` (failed_attempts = 6) | `audit_log` |
| MTTD / MTTR (сценарій етапу 2, детектор) | MTTD 64,4 с (перший `login_failed` 16:44:29.32 → `brute_force_detected` 16:45:33.73; включає 61-секундну паузу сценарію — детекція відбувається на наступній спробі) / MTTR 0,07 с (→ перший 429 о 16:45:33.79) | `audit_log` |
| MTTD / MTTR (T12) | 0,43 с від першого `login_failed` (17:05:17.24) до першого 429 (17:05:17.67) — спрацював slowapi; детектор не досяг порогу (3 невдачі < 5) | `audit_log` |
| Бекап / відновлення | `app_20261015_164233.db.enc`, права `-rw-------`, бекап — секунди / `integrity_check=ok, users=5`; з іншим ключем — `InvalidToken` | `backup_db`, `restore_db` |
| RPO / RTO | RPO = інтервал між ручними бекапами (рекомендація — щоденний за розкладом, 3-2-1); RTO ≈ хвилини (розшифрування + заміна файлу) | оцінка |

## 11. План покращень

| Пріоритет | Захід | Загроза, що знижується | Строк |
|---|---|---|---|
| 1 | Копія ключів шифрування в сейфі / KMS, процедура ротації (`scripts/rotate_keys.py`) | Втрата ключа (R6) | 2 тижні |
| 2 | MFA (TOTP) для admin/teacher | Spoofing, фішинг (R4, R8) | 1 місяць |
| 3 | Відкликання токенів (denylist `jti`) і коротший TTL для admin | Крадіжка JWT (R4) | 1 місяць |
| 4 | Прогресивна затримка / CAPTCHA замість жорсткого блокування за username | DoS через lockout (R9, F-08) | 1 місяць |
| 5 | Hash-chain для `audit_log` або відправка в зовнішній SIEM | Repudiation (R10) | 2 місяці |
| 6 | Щоденний бекап за розкладом з копією поза хостом (3-2-1) | Втрата даних | 2 тижні |
| 7 | CI (GitHub Actions) з Bandit, pip-audit, Trivy; регулярне оновлення базового образу | Вразливі компоненти (R7, F-07) | 1 місяць |

## 12. Висновок

Система готова до використання як навчальний стенд і проходить усі автоматичні перевірки: 12/12 мінітестів, `security_check.sh` PASSED, pip-audit 0, Bandit 0, Trivy CRITICAL 0. Усі знахідки рівня High (F-01…F-04) виправлено й перевірено повторно. Перед промисловою експлуатацією обов'язкові: MFA для привілейованих ролей, захищене зберігання ключів шифрування з резервною копією та сертифікат від довіреного CA.
