from datetime import datetime, timedelta, timezone
from hashlib import sha256
from secrets import token_hex

from fastapi import HTTPException, status
import jwt

from app.config import settings


def generate_refresh_token() -> tuple[str, str]:
    token = token_hex(64)

    hashed_token = sha256(token.encode("utf-8")).hexdigest()

    return token, hashed_token


def generate_access_token(user_id: int) -> str:
    if not settings.JWT_KEY:
        raise RuntimeError("JWT_SECRET is not configured")

    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(minutes=15),
    }

    return jwt.encode(
        payload,
        settings.JWT_KEY,
        algorithm="HS256",
    )

def generate_email_token_for_links(user_id: int) -> str:
    verification_token = jwt.encode(
            {
                "sub": str(user_id), 
                "exp": datetime.utcnow() + timedelta(days=1),
                "scope": "email_verification"
            }, 
            key=settings.JWT_KEY, 
            algorithm="HS256"
        )

    return verification_token

def generate_email_token_for_code(user_id: int, verification_code: str, attempt: int = 1) -> str:
    verification_token = jwt.encode(
            {
                "sub": str(user_id),
                "code": str(verification_code),  # Сам код внутри токена (или его хэш)
                "exp": datetime.utcnow() + timedelta(minutes=15),
                "attempt": attempt,
                "scope": "email_verification"
            },
            key=settings.JWT_KEY,
            algorithm="HS256"
        )

    return verification_token

def decode_token_ignoring_expiration(token: str) -> dict:
    try:
        # options={"verify_exp": False} отключает валидацию времени жизни,
        # но валидация подписи (SECRET_KEY) и алгоритма остаётся активной!
        payload = jwt.decode(
            token, 
            settings.JWT_KEY, 
            algorithms="HS256", 
            options={"verify_exp": False}
        )
        return payload
    except jwt.InvalidSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token signature is invalid"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token structure"
        )