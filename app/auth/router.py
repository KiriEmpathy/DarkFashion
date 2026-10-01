from secrets import token_hex, token_urlsafe

from hashlib import sha256

from base64 import urlsafe_b64encode

from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.params import Depends
from fastapi.responses import JSONResponse, RedirectResponse
import httpx

from app.auth.dependencies import (
    get_current_user,
    get_refresh_tokens_use_case,
    get_resend_verification_use_case,
    get_sign_out_use_case,
    get_sign_up_user_use_case,
    get_sign_in_user_with_password_use_case,
    get_sign_in_with_oauth_use_case,
    get_verify_email_use_case,
)
from app.auth.schemas.api import ResendVerificationRequest, SignInRequest, SignUpRequest, UserResponse, VerifyCodeRequest
from app.auth.use_cases.refresh_tokens_use_case import RefreshTokensUseCase
from app.auth.use_cases.resend_verification_code_use_case import ResendVerificationCodeUseCase
from app.auth.use_cases.sign_up_with_password_use_case import SignUpUserWithPasswordUseCase
from app.auth.use_cases.sign_in_with_password_use_case import SignInWithPasswordUseCase
from app.auth.use_cases.sign_in_with_oauth_use_case import SignInWithOAuthUseCase
from app.auth.use_cases.verify_email_use_case import VerifyEmailUseCase
from app.auth.use_cases.sign_out_use_case import SignOutUseCase
from app.config import settings
from app.oauth import oauth
from app.users.models import User
from app.users.builders import build_user_response


router = APIRouter(prefix="/auth", tags=["Авторизация"])


@router.post("/sign-up")
async def sign_up(
    data: SignUpRequest,
    request: Request,
    response: Response,
    usecase: SignUpUserWithPasswordUseCase = Depends(get_sign_up_user_use_case),
):

    user, access_token, refresh_token, verification_token = await usecase.execute(data, request)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 15,
    )

    response.set_cookie(
        key="verification_token",
        value=verification_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 1,
    )

    return user


@router.post("/sign-in")
async def sign_in(
    data: SignInRequest,
    request: Request,
    response: Response,
    usecase: SignInWithPasswordUseCase = Depends(
        get_sign_in_user_with_password_use_case
    ),
):

    user, access_token, refresh_token = await usecase.execute(data, request)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 15,
    )

    return user


@router.get("/vk/login")
async def vk_login(request: Request):
    # PKCE
    code_verifier = token_urlsafe(64)

    code_challenge = (
        urlsafe_b64encode(
            sha256(code_verifier.encode("utf-8")).digest()
        )
        .decode("utf-8")
        .rstrip("=")
    )

    # OAuth state
    state = token_urlsafe(32)

    # Сохраняем всё, что понадобится callback
    request.session["vk_state"] = state
    request.session["vk_code_verifier"] = code_verifier

    params = {
        "response_type": "code",
        "client_id": settings.VK_CLIENT_ID,
        "redirect_uri": settings.VK_REDIRECT_URI,
        "state": state,
        "scope": "vkid.personal_info email",
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }

    url = (
        "https://id.vk.com/authorize?"
        + urlencode(params)
    )

    return RedirectResponse(url=url, status_code=302)

@router.get("/vk/callback")
async def vk_callback(
    request: Request,
    code: str,
    state: str,
    device_id: str,
    usecase: SignInWithOAuthUseCase = Depends(
        get_sign_in_with_oauth_use_case
    ),
):
    # ==========================================
    # 1. Проверяем state
    # ==========================================

    saved_state = request.session.pop("vk_state", None)

    if not saved_state:
        raise HTTPException(
            status_code=400,
            detail="OAuth-сессия не найдена",
        )

    if saved_state != state:
        raise HTTPException(
            status_code=400,
            detail="Некорректный OAuth state",
        )

    # ==========================================
    # 2. Забираем PKCE verifier
    # ==========================================

    code_verifier = request.session.pop(
        "vk_code_verifier",
        None,
    )

    if not code_verifier:
        raise HTTPException(
            status_code=400,
            detail="PKCE code_verifier не найден",
        )

    # ==========================================
    # 3. Обмениваем code на VK tokens
    # ==========================================

    token_payload = {
        "grant_type": "authorization_code",
        "code": code,
        "device_id": device_id,
        "client_id": settings.VK_CLIENT_ID,
        "redirect_uri": settings.VK_REDIRECT_URI,
        "state": state,
        "code_verifier": code_verifier,
    }

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_response = await client.post(
            "https://id.vk.com/oauth2/auth",
            data=token_payload,
        )

    token_data = token_response.json()

    if token_response.is_error or token_data.get("error"):
        raise HTTPException(
            status_code=400,
            detail=token_data.get(
                "error_description",
                token_data.get(
                    "error",
                    "Ошибка при получении VK token",
                ),
            ),
        )

    vk_access_token = token_data.get("access_token")

    if not vk_access_token:
        raise HTTPException(
            status_code=400,
            detail="VK не вернул access_token",
        )

    # ==========================================
    # 4. Получаем VK profile
    # ==========================================

    async with httpx.AsyncClient(timeout=10.0) as client:
        profile_response = await client.post(
            "https://id.vk.com/oauth2/user_info",
            data={
                "client_id": settings.VK_CLIENT_ID,
                "access_token": vk_access_token,
            },
        )

    profile_data = profile_response.json()

    if profile_response.is_error or profile_data.get("error"):
        raise HTTPException(
            status_code=400,
            detail=profile_data.get(
                "error_description",
                "Не удалось получить профиль VK ID",
            ),
        )

    # ==========================================
    # 5. Нормализуем VK profile
    #    под твой общий OAuth use case
    # ==========================================

    vk_user = profile_data.get("user", {})

    provider_id = vk_user.get("user_id")

    if not provider_id:
        raise HTTPException(
            status_code=400,
            detail="VK не вернул user_id",
        )

    first_name = vk_user.get("first_name", "")
    last_name = vk_user.get("last_name", "")

    name = f"{first_name} {last_name}".strip()

    user_info = {
        "iss": "https://id.vk.com",
        "sub": str(provider_id),
        "email": profile_data.get("email"),
        "name": name or "VK User",
        "picture": vk_user.get("avatar"),
        "given_name": first_name,
        "family_name": last_name,
    }

    # ==========================================
    # 6. Твой общий OAuth use case
    # ==========================================

    user, access_token, refresh_token = await usecase.execute(
        user_info=user_info,
        provider="vk",
        request=request,
    )

    # ==========================================
    # 7. Выдаём cookies твоего приложения
    # ==========================================

    response = JSONResponse(
        content={
            "id": user.id,
            "name": user.name,
            "email": user.email,
        }
    )

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="lax",
        max_age=60 * 15,
        path="/",
    )

    return response



@router.get("/google")
async def login_google(request: Request):
    return await oauth.google.authorize_redirect(request, settings.GOOGLE_REDIRECT_URI)


@router.get("/google/callback")
async def callback_google(
    request: Request,
    response: Response,
    usecase: SignInWithOAuthUseCase = Depends(get_sign_in_with_oauth_use_case),
):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(400, "Ошибка авторизации")

    user_info = token.get("userinfo")

    user, access_token, refresh_token = await usecase.execute(user_info=user_info, provider="google", request=request)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 15,
    )

    return user


@router.get("/me")
async def get_user(current_user: User = Depends(get_current_user)) -> UserResponse:
    return build_user_response(current_user)


@router.post("/refresh")
async def refresh_tokens(
    request: Request,
    response: Response,
    usecase: RefreshTokensUseCase = Depends(get_refresh_tokens_use_case),
):
    access_token, refresh_token = await usecase.execute(request)

    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 7,
        path="/",
    )

    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 15,
    )

@router.post("/sign-out", status_code=status.HTTP_200_OK)
async def sign_out(
    request: Request,
    response: Response,
    usecase: SignOutUseCase = Depends(get_sign_out_use_case),
):
    # 1. Извлекаем refresh_token из кук запроса
    refresh_token_hash = request.cookies.get("refresh_token")
    
    # 2. Если токен есть, инвалидируем сессию в БД через UseCase
    if refresh_token_hash:
        await usecase.execute(refresh_token_hash=refresh_token_hash)

    # 3. Стираем куки на клиенте (выставляем max_age=0 и убираем значение)
    # Важно: path, secure и samesite должны совпадать с тем, как они ставились в sign-in
    response.delete_cookie(
        key="access_token",
        secure=True,
        samesite="none"
    )
    response.delete_cookie(
        key="refresh_token",
        path="/",
        secure=True,
        samesite="none"
    )

    return {"detail": "Successfully logged out"}

@router.put("/verify")
async def verify_email(
    request: Request,
    response: Response,
    code: VerifyCodeRequest,
    usecase: VerifyEmailUseCase = Depends(get_verify_email_use_case)
):
    verification_token = request.cookies.get("verification_token")

    await usecase.execute(code.code, token=verification_token)

    response.delete_cookie("verification_token")
    
    return {"status": "success", "message": "Email successfully verified!"}

@router.post(
    "/resend-verification", 
    status_code=status.HTTP_200_OK,
    summary="Повторная отправка кода верификации"
)
@router.post(
    "/resend-verification", 
    status_code=status.HTTP_200_OK,
    summary="Повторная отправка кода верификации"
)
@router.post(
    "/resend-verification", 
    status_code=status.HTTP_200_OK,
    summary="Повторная отправка кода верификации"
)
@router.post(
    "/resend-verification", 
    status_code=status.HTTP_200_OK,
    summary="Повторная отправка кода верификации через Cookies"
)
async def resend_verification(
    request: Request,
    response: Response,
    use_case: ResendVerificationCodeUseCase = Depends(get_resend_verification_use_case)
):
    # 1. Достаем токен напрямую из кук запроса
    # Замените "verification_token" на точное имя вашей куки
    verification_token = request.cookies.get("verification_token")
    
    if not verification_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token missing in cookies"
        )
        
    # 2. Выполняем бизнес-логику (декодирование, проверка попыток, генерация нового кода)
    new_token = await use_case.execute(expired_token=verification_token)
    
    # 3. Записываем новый обновленный токен обратно в куки ответа
    response.set_cookie(
        key="verification_token",
        value=verification_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=60 * 60 * 24 * 1,
    )
    
    return {
        "status": "success",
        "message": "Новый код верификации отправлен на email"
    }