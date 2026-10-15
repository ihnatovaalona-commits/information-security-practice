"""Ротація ключа шифрування: python -m scripts.rotate_keys

1. Старий ключ -> ENCRYPTION_KEY_OLD, новий -> ENCRYPTION_KEY (у .env), перезапуск api.
2. Скрипт перешифровує всі PII новим ключем (MultiFernet.rotate()).
3. Після успіху ENCRYPTION_KEY_OLD видаляють з .env.
"""
from sqlalchemy import text

from app.crypto.key_manager import get_fernet
from app.database import SessionLocal


def _rotate(value: str | None) -> str | None:
    if not value:
        return value
    return get_fernet().rotate(value.encode("ascii")).decode("ascii")


def rotate() -> None:
    db = SessionLocal()
    try:
        rows = db.execute(text(
            "SELECT id, encrypted_email, encrypted_phone FROM users"
        )).fetchall()
        for user_id, email, phone in rows:
            db.execute(
                text("UPDATE users SET encrypted_email = :email, encrypted_phone = :phone "
                     "WHERE id = :id"),
                {"email": _rotate(email), "phone": _rotate(phone), "id": user_id},
            )
        db.commit()
        print(f"Перешифровано користувачів: {len(rows)}")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    rotate()
