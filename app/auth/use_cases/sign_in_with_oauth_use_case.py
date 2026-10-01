from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.repository.provider_repo import ProviderRepository
from app.auth.types import AuthProvider
from app.auth.use_cases.issue_tokens_use_case import IssueTokensUseCase
from app.users.repository import UserRepository
from app.users.use_cases.create_user_use_case import CreateUserUseCase


class SignInWithOAuthUseCase:
    def __init__(
        self,
        provider_repository: ProviderRepository,
        user_repository: UserRepository,
        create_user_usecase: CreateUserUseCase,
        issue_tokens_usecase: IssueTokensUseCase,
        session: AsyncSession,
    ):
        self.provider_repo = provider_repository
        self.user_repo = user_repository
        self.create_user = create_user_usecase
        self.issue_tokens = issue_tokens_usecase
        self.session = session

    async def execute(self, user_info: dict, provider: str, request: Request):
        provider_id = str(user_info.get("sub"))
        email = user_info.get("email")
        name = user_info.get("name", "OAuth User")

        # 1. Безопасная обработка аватарок (Google-специфичный код не сломает VK)
        avatar_url = user_info.get("picture")
        if avatar_url and "=s96-c" in avatar_url:
            avatar_url = avatar_url.replace("=s96-c", "=s256-c")

        # 2. Проверка ID провайдера
        if not provider_id:
            raise HTTPException(400, "Не удалось получить ID от провайдера")

        # 3. Страховка на случай отсутствия email у VK
        if not email:
            if provider == "vk":
                email = f"vk_{provider_id}@vk.user" # Временная заглушка-заполнитель
            else:
                raise HTTPException(400, "Не удалось получить email от провайдера")

        # 4. Ищем пользователя по динамическому провайдеру (а не только google)
        user = await self.provider_repo.find_user_by_provider(
            provider=provider, 
            provider_id=provider_id
        )

        if not user:
            user = await self.create_user.execute(name, email)
            await self.user_repo.mark_as_verified(user_id=user.id)

            # Предполагаем, что в AuthProvider есть AuthProvider.VK (или используем строку provider)
            # Если AuthProvider — это Enum, убедитесь, что добавили туда VK (например, AuthProvider.VK = "vk")
            db_provider = AuthProvider(provider) if hasattr(AuthProvider, provider.upper()) else provider

            await self.provider_repo.create_provider(
                user_id=user.id, 
                provider=db_provider, 
                provider_id=provider_id
            )

        access_token, refresh_token = await self.issue_tokens.execute(user, request)

        await self.session.commit()
        return user, access_token, refresh_token
