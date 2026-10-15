import time

from jwt import PyJWTError as JWTError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from app.audit.logger import get_client_ip, log_event
from app.auth.jwt_handler import verify_token
from app.database import SessionLocal

SKIP_PATHS = {"/health", "/docs", "/redoc", "/openapi.json", "/favicon.ico"}
ACTION_BY_CODE = {401: "unauthorized", 403: "access_denied", 429: "rate_limited"}


def _user_id_from_token(request: Request) -> int | None:
    """WHO: middleware працює до get_current_user, тому беремо sub з JWT (з перевіркою підпису)."""
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None
    try:
        return int(verify_token(auth[7:]).get("sub"))
    except (JWTError, TypeError, ValueError):
        return None


def _write(request: Request, action: str, status: str, code: int, started: float) -> None:
    db = SessionLocal()
    try:
        log_event(db, action, status, get_client_ip(request),
                  user_id=_user_id_from_token(request),
                  http_method=request.method, endpoint=request.url.path,
                  status_code=code,
                  details={"duration_ms": round((time.perf_counter() - started) * 1000, 1)})
    finally:
        db.close()


class AuditMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path in SKIP_PATHS:
            return await call_next(request)

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Необроблений виняток стане 500 у ServerErrorMiddleware — фіксуємо його тут
            await run_in_threadpool(_write, request, "server_error", "error", 500, started)
            raise
        code = response.status_code

        if request.method == "GET" and code < 400:
            return response  # успішне читання не журналюємо (шум)

        if code >= 500:
            action, status = "server_error", "error"
        elif code in ACTION_BY_CODE:
            action, status = ACTION_BY_CODE[code], "failure"
        else:
            action = f"http_{request.method.lower()}"
            status = "success" if code < 400 else "failure"

        await run_in_threadpool(_write, request, action, status, code, started)  # не блокуємо event loop
        return response
