import random
import uuid

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.repository.provider_repo import ProviderRepository
from app.auth.schemas.api import SignUpRequest
from app.auth.types import AuthProvider
from app.auth.use_cases.issue_tokens_use_case import IssueTokensUseCase
from app.shared.utils.generate_tokens import  generate_email_token_for_code
from app.users.use_cases.create_user_use_case import CreateUserUseCase

from app.mail import MailService


class SignUpUserWithPasswordUseCase:
    def __init__(
        self,
        provider_repository: ProviderRepository,
        create_user_usecase: CreateUserUseCase,
        issue_tokens_usecase: IssueTokensUseCase,
        mail_service: MailService,
        session: AsyncSession,
    ):
        self.session = session
        self.provider_repository = provider_repository
        self.create_user_usecase = create_user_usecase
        self.issue_tokens_usecase = issue_tokens_usecase
        self.mail_service = mail_service

    async def execute(self, data: SignUpRequest, request: Request):
        provider = AuthProvider.PASSWORD
        provider_id = str(uuid.uuid4())

        user = await self.create_user_usecase.execute(data.name, data.email, data.password)

        await self.provider_repository.create_provider(user.id, provider, provider_id)

        access_token, refresh_token = await self.issue_tokens_usecase.execute(
            user, request
        )

        verification_code = f"{random.randint(1000, 9999)}"

        verification_token = generate_email_token_for_code(user.id, verification_code, attempt=1)
        
        await self.mail_service.send_verification_code(
            email=user.email, 
            code=verification_code
        )

        await self.session.commit()

        return user, access_token, refresh_token, verification_token