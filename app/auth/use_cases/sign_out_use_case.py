from fastapi import HTTPException, status
import jwt

from app.auth.repository.session_repo import SessionRepository

class SignOutUseCase:
    def __init__(self, session_repository: SessionRepository):
        self.session_repository = session_repository

    async def execute(self, refresh_token_hash: str) -> None:
        session = self.session_repository.find_by_refresh_token_hash(refresh_token_hash=refresh_token_hash)
        if session:
            await self.session_repository.delete_by_refresh_token_hash(refresh_token_hash=refresh_token_hash)
            await self.session_repository.session.commit() 