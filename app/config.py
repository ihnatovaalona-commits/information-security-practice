import os

# Секрет лише з оточення, без fallback: без ключа застосунок не стартує
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "")
if len(SECRET_KEY) < 32:
    raise RuntimeError(
        "JWT_SECRET_KEY не задано або коротший за 32 символи (openssl rand -hex 32)"
    )

ALGORITHM = "HS256"

# Время жизни access-токена — 30 минут
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
)

# Время жизни refresh-токена — 7 дней
REFRESH_TOKEN_EXPIRE_DAYS = int(
    os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", "7")
)

# Разрешённые источники для CORS
CORS_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:8000",
    ).split(",")
    if origin.strip()
]