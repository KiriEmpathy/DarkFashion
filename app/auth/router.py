from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.params import Depends
from fastapi.responses import RedirectResponse
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
    redirect_uri = "https://localhost:443/auth/vk/callback"
    return await oauth.vk.authorize_redirect(request, redirect_uri)

@router.get("/vk/callback")
async def callback_vk(
    request: Request,
    response: Response,
    usecase: SignInWithOAuthUseCase = Depends(get_sign_in_with_oauth_use_case),
):
    # 1. Получаем токен от VK (Authlib автоматически обменяет code на токен)
    try:
        token = await oauth.vk.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Ошибка авторизации")

    user_id = token.get("user_id")
    email = token.get("email") 
    access_token_vk = token.get("access_token")

    # 2. VK не отдает профиль в токене, запрашиваем данные вручную через httpx
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://vk.com",
                params={
                    "user_ids": user_id,
                    "fields": "photo_200,first_name,last_name",
                    "access_token": access_token_vk,
                    "v": "5.131"
                }
            )
            resp_data = resp.json()
            
            if "error" in resp_data:
                raise HTTPException(status_code=400, detail="Ошибка получения профиля VK")
                
            vk_profile = resp_data["response"][0]
    except Exception:
        raise HTTPException(status_code=400, detail="Не удалось связаться с API VK")

    # 3. Маппим данные от VK в формат, похожий на Google userinfo, 
    # чтобы ваш UseCase мог их корректно обработать
    user_info = {
        "iss": "https://vk.com",
        "sub": str(user_id),  # Уникальный ID пользователя в VK
        "email": email,       # Может быть None, если у пользователя нет email в VK
        "name": f"{vk_profile.get('first_name')} {vk_profile.get('last_name')}",
        "picture": vk_profile.get("photo_200"),
        "given_name": vk_profile.get("first_name"),
        "family_name": vk_profile.get("last_name"),
    }

    # 4. Передаем нормализованные данные в ваш существующий UseCase
    user, access_token, refresh_token = await usecase.execute(user_info, request)

    # 5. Устанавливаем те же самые куки
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
async def resend_verification(
    request: ResendVerificationRequest,
    use_case: ResendVerificationCodeUseCase = Depends(get_resend_verification_use_case)
):
    new_token = await use_case.execute(expired_token=request.expired_token)
    
    return {
        "status": "success",
        "message": "Новый код верификации отправлен на email",
        "verification_token": new_token
    }