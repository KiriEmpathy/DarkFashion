import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import APIKeyCookie
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.repository.provider_repo import ProviderRepository
from app.auth.repository.session_repo import SessionRepository
from app.auth.use_cases.issue_tokens_use_case import IssueTokensUseCase
from app.auth.use_cases.refresh_tokens_use_case import RefreshTokensUseCase
from app.auth.use_cases.sign_up_with_password_use_case import SignUpUserWithPasswordUseCase
from app.auth.use_cases.sign_in_with_password_use_case import SignInWithPasswordUseCase
from app.auth.use_cases.sign_in_with_oauth_use_case import SignInWithOAuthUseCase
from app.auth.use_cases.sign_out_use_case import SignOutUseCase
from app.auth.use_cases.verify_email_use_case import VerifyEmailUseCase
from app.config import settings
from app.database import get_session
from app.mail import MailService
from app.users.models import User
from app.users.dependencies import get_user_repo
from app.users.repository import UserRepository
from app.users.use_cases.create_user_use_case import CreateUserUseCase
from app.auth.use_cases.resend_verification_code_use_case import ResendVerificationCodeUseCase


def get_provider_repo(
    session: AsyncSession = Depends(get_session),
) -> ProviderRepository:
    return ProviderRepository(session)


def get_session_repo(session: AsyncSession = Depends(get_session)) -> SessionRepository:
    return SessionRepository(session)


def get_sign_up_user_use_case(
    session: AsyncSession = Depends(get_session),
    provider_repo: ProviderRepository = Depends(get_provider_repo),
    user_repo: UserRepository = Depends(get_user_repo),
    session_repo: SessionRepository = Depends(get_session_repo),
    mail_service: MailService = Depends(MailService)
) -> SignUpUserWithPasswordUseCase:

    create_user = CreateUserUseCase(user_repo)
    issue_tokens = IssueTokensUseCase(session_repo)

    return SignUpUserWithPasswordUseCase(
        provider_repository=provider_repo,
        create_user_usecase=create_user,
        issue_tokens_usecase=issue_tokens,
        mail_service=mail_service,
        session=session,
    )


def get_sign_in_user_with_password_use_case(
    session: AsyncSession = Depends(get_session),
    user_repo: UserRepository = Depends(get_user_repo),
    session_repo=Depends(get_session_repo),
) -> SignInWithPasswordUseCase:

    issue_tokens = IssueTokensUseCase(session_repo)

    return SignInWithPasswordUseCase(
        issue_tokens_usecase=issue_tokens,
        user_repository=user_repo,
        session=session,
    )


def get_sign_in_with_oauth_use_case(
    session: AsyncSession = Depends(get_session),
    provider_repo=Depends(get_provider_repo),
    user_repo=Depends(get_user_repo),
    session_repo=Depends(get_session_repo),
) -> SignInWithOAuthUseCase:

    return SignInWithOAuthUseCase(
        provider_repository=provider_repo,
        user_repository=user_repo,
        create_user_usecase=CreateUserUseCase(user_repo),
        issue_tokens_usecase=IssueTokensUseCase(session_repo),
        session=session,
    )


security = APIKeyCookie(name="access_token", auto_error=False)


async def get_current_user(
    token: str | None = Depends(security),
    user_repo: UserRepository = Depends(get_user_repo),
) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "code": "ACCESS_TOKEN_MISSING",
                "message": "ACCESS_TOKEN_MISSING",
            },
        )

    try:
        payload = jwt.decode(token, key=settings.JWT_KEY, algorithms=["HS256"])
        user_id: str = payload.get("sub")

        if user_id is None:
            raise jwt.InvalidTokenError()

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "TOKEN_EXPIRED", "message": "TOKEN_EXPIRED"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_TOKEN", "message": "INVALID_TOKEN"},
        )

    user = await user_repo.find_by_id(int(user_id))

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "USER_NOT_FOUND", "message": "User no longer exists"},
        )

    return user


def get_refresh_tokens_use_case(
    session_repo: SessionRepository = Depends(get_session_repo),
    session: AsyncSession = Depends(get_session),
) -> RefreshTokensUseCase:
    """
    Фабрика для сборки RefreshTokensUsecase.
    Просто собирает зависимости и возвращает готовый объект.
    """

    return RefreshTokensUseCase(session_repo=session_repo, session=session)

def get_sign_out_use_case(
    session: AsyncSession = Depends(get_session)
) -> SignOutUseCase:
    session_repo = SessionRepository(session=session)
    return SignOutUseCase(session_repository=session_repo)

def get_verify_email_use_case(
    session: AsyncSession = Depends(get_session),
    mail_service: MailService = Depends(MailService)
) -> VerifyEmailUseCase:
    user_repo = UserRepository(session=session)
    return VerifyEmailUseCase(user_repository=user_repo, mail_service=mail_service)

async def get_resend_verification_use_case(
    session: AsyncSession = Depends(get_session)
) -> ResendVerificationCodeUseCase:
    """
    Фабрика для сборки ResendVerificationCodeUseCase.
    Принимает сессию БД из get_session и внедряет её во все слои.
    """
    user_repository = UserRepository(session)
    mail_service = MailService()
    
    return ResendVerificationCodeUseCase(
        user_repository=user_repository,
        mail_service=mail_service,
        session=session
    )