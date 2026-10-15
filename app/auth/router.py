
from fastapi import APIRouter, Depends, HTTPException, Request, status
from jose import JWTError
from sqlalchemy.orm import Session

from app.audit.detector import check_brute_force, check_off_hours_access
from app.audit.logger import (
    get_client_ip,
    log_event,
    log_login_failed,
    log_login_success,
)
from app.auth.dependencies import get_current_user
from app.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    verify_token,
)
from app.crypto.encryption import blind_index
from app.database import get_db
from app.middleware.rate_limiter import limiter
from app.models import Role, User
from app.schemas import (
    LoginRequest,
    TokenRefreshRequest,
    TokenResponse,
    UserCreate,
    UserInfo,
    UserResponse,
)
from app.security import hash_password, verify_password


router = APIRouter(prefix="/auth", tags=["Authentication"])


def _primary_role(user: User) -> str:
    return user.roles[0].name if user.roles else "student"


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
@limiter.limit("10/minute")
def register(
    request: Request,
    user_data: UserCreate,
    db: Session = Depends(get_db),
):
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username вже зайнятий",
        )

    # Fernet щоразу дає інший шифротекст, тому унікальність — через сліпий індекс (HMAC)
    if db.query(User).filter(
        User.email_index == blind_index(user_data.email)
    ).first():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email вже зареєстровано",
        )

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        password_hash=hash_password(user_data.password),
    )

    student_role = db.query(Role).filter(Role.name == "student").first()
    if student_role:
        new_user.roles.append(student_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    log_event(
        db, "user_registered", "success", get_client_ip(request),
        user_id=new_user.id, username=new_user.username,
        http_method="POST", endpoint="/auth/register", status_code=201,
    )

    return new_user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db),
):
    ip = get_client_ip(request)

    # 1. Brute Force перевіряємо до перевірки пароля
    if check_brute_force(db, ip, credentials.username):
        log_login_failed(db, credentials.username, ip, reason="brute_force_blocked")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Забагато невдалих спроб. Спробуйте через 5 хвилин.",
        )

    # 2. Однакова відповідь для «немає користувача» і «невірний пароль»
    user = (
        db.query(User)
        .filter(User.username == credentials.username)
        .first()
    )

    if not user or not verify_password(
        credentials.password, user.password_hash
    ):
        log_login_failed(db, credentials.username, ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невірний логін або пароль",
        )

    if not user.is_active:
        log_login_failed(db, credentials.username, ip, reason="inactive")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Акаунт деактивовано",
        )

    check_off_hours_access(db, user.id, user.username, ip)
    log_login_success(db, user.id, user.username, ip)

    return TokenResponse(
        access_token=create_access_token(user.id, _primary_role(user)),
        refresh_token=create_refresh_token(user.id),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(body: TokenRefreshRequest, db: Session = Depends(get_db)):
    try:
        payload = verify_token(body.refresh_token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Потрібен refresh token",
            )
        user_id = int(payload["sub"])
    except HTTPException:
        raise
    except (JWTError, ValueError, TypeError, KeyError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невалідний refresh token",
        )

    user = db.get(User, user_id)

    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Користувача не знайдено",
        )

    return TokenResponse(
        access_token=create_access_token(user.id, _primary_role(user)),
        refresh_token=create_refresh_token(user.id),
    )


@router.get("/me", response_model=UserInfo)
def me(current_user: User = Depends(get_current_user)):
    return UserInfo(
        id=current_user.id,
        username=current_user.username,
        email=current_user.email,
        full_name=current_user.full_name,
        roles=[role.name for role in current_user.roles],
    )
