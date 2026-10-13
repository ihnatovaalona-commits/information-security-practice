import re
from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator


NAME_RE = re.compile(r"^[A-Za-zА-Яа-яІіЇїЄєҐґ'’ʼ .\-]+$")


class UserCreate(BaseModel):
    username: str = Field(
        ...,
        min_length=3,
        max_length=30,
        pattern=r"^[a-zA-Z0-9_]+$",
        description="Латиница, цифры, подчёркивание",
    )
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72)
    full_name: str = Field(..., min_length=2, max_length=100)

    @field_validator("password")
    @classmethod
    def password_strength(cls, value: str) -> str:
        if not re.search(r"[A-Z]", value):
            raise ValueError("Пароль должен содержать заглавную букву")
        if not re.search(r"[a-z]", value):
            raise ValueError("Пароль должен содержать строчную букву")
        if not re.search(r"\d", value):
            raise ValueError("Пароль должен содержать цифру")
        return value

    @field_validator("full_name")
    @classmethod
    def full_name_allowlist(cls, value: str) -> str:
        if not NAME_RE.fullmatch(value):
            raise ValueError(
                "Имя может содержать только буквы, пробел, апостроф, дефис и точку"
            )
        return value.strip()


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class LoginRequest(BaseModel):
    username: str = Field(..., max_length=30)
    password: str = Field(..., max_length=72)


class LoginResponse(BaseModel):
    message: str
    user_id: int
    username: str
    roles: list[str] = []