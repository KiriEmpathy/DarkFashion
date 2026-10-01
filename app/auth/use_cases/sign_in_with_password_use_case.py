import bcrypt
from fastapi import HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.schemas.api import SignInRequest
from app.auth.use_cases.issue_tokens_use_case import IssueTokensUseCase
from app.users.models import User
from app.users.repository import UserRepository



class SignInWithPasswordUseCase:
    def __init__(
        self,
        issue_tokens_usecase: IssueTokensUseCase,
        user_repository: UserRepository,
        session: AsyncSession,
    ):
        self.session = session
        self.issue_tokens_usecase = issue_tokens_usecase
        self.user_repository = user_repository

    @staticmethod
    def _verify_password(user: User, plain_password):
        hashed_password = (
            user.password_hash 
            if user 
            else "$2b$12$L7I1ZzJ1zJ1zJ1zJ1zJ1z.1zJ1zJ1zJ1zJ1zJ1zJ1zJ1zJ1zJ1zJ."
        )
        
        is_valid = bcrypt.checkpw(
            plain_password.encode("utf-8"), 
            hashed_password.encode("utf-8")
        )
        
        return user is not None and is_valid

    async def execute(self, data: SignInRequest, request: Request):
        user = await self.user_repository.find_by_email(data.email)

        if not self._verify_password(user, data.password):
            raise HTTPException(401, "Неверный логин или пароль")

        
        access_token, refresh_token = await self.issue_tokens_usecase.execute(user, request)

        await self.session.commit()

        return user, access_token, refresh_token