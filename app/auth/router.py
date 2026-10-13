from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Role, User
from app.schemas import LoginRequest, LoginResponse, UserCreate, UserResponse
from app.security import hash_password, verify_password


router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    # Проверяем уникальность имени пользователя
    existing_user = (
        db.query(User)
        .filter(User.username == user_data.username)
        .first()
    )
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username вже зайнятий",
        )

    # Проверяем уникальность электронной почты
    existing_email = (
        db.query(User)
        .filter(User.email == user_data.email)
        .first()
    )
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email вже зареєстровано",
        )

    # Создаём пользователя, сохраняя только хеш пароля
    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        password_hash=hash_password(user_data.password),
    )

    # Новому пользователю назначаем роль student
    student_role = (
        db.query(Role)
        .filter(Role.name == "student")
        .first()
    )
    if student_role:
        new_user.roles.append(student_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


@router.post("/login", response_model=LoginResponse)
def login(
    credentials: LoginRequest,
    db: Session = Depends(get_db),
):
    user = (
        db.query(User)
        .filter(User.username == credentials.username)
        .first()
    )

    # Для отсутствующего пользователя и неверного пароля
    # возвращаем одинаковое сообщение
    if not user or not verify_password(
        credentials.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невірний логін або пароль",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Акаунт деактивовано",
        )

    return LoginResponse(
        message="Вхід успішний",
        user_id=user.id,
        username=user.username,
        roles=[role.name for role in user.roles],
    )