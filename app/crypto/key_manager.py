import os
from functools import lru_cache

from cryptography.fernet import Fernet, MultiFernet


class EncryptionKeyError(RuntimeError):
    """Ключ шифрування відсутній або має неправильний формат."""


def _load_key(env_name: str) -> Fernet | None:
    raw = os.getenv(env_name)
    if not raw:
        return None
    try:
        return Fernet(raw.encode())
    except ValueError as exc:
        raise EncryptionKeyError(
            f"{env_name}: неправильний формат (потрібно 32 байти urlsafe-base64)"
        ) from exc


@lru_cache(maxsize=1)
def get_fernet() -> MultiFernet:
    """MultiFernet([поточний, (старий)]): шифрує поточним, розшифровує будь-яким."""
    current = _load_key("ENCRYPTION_KEY")
    if current is None:
        raise EncryptionKeyError(
            "ENCRYPTION_KEY не задано: python -m scripts.generate_key і додайте в .env"
        )
    keys = [current]
    old = _load_key("ENCRYPTION_KEY_OLD")
    if old is not None:
        keys.append(old)
    return MultiFernet(keys)


@lru_cache(maxsize=1)
def get_blind_index_key() -> bytes:
    """Окремий ключ для HMAC сліпого індексу (не збігається з ENCRYPTION_KEY)."""
    raw = os.getenv("BLIND_INDEX_KEY", "")
    if len(raw) < 32:
        raise EncryptionKeyError("BLIND_INDEX_KEY закороткий (openssl rand -hex 32 у .env)")
    return raw.encode()
