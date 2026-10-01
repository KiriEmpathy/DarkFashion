from datetime import datetime
from hashlib import sha256

from fastapi import HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.repository.session_repo import SessionRepository
from app.shared.utils.generate_tokens import (
    generate_access_token,
    generate_refresh_token,
)


class RefreshTokensUseCase:
    def __init__(self, session_repo: SessionRepository, session: AsyncSession):
        self.session_repo = session_repo
        self.session = session

    async def execute(self, request: Request):
        token: str | None = request.cookies.get("refresh_token")

        if not token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Пшёл вон"
            )

        session_id = token.partition(".")[0]

        try:
            session_id = int(session_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )

        token = token.partition(".")[2]

        old_hashed_token = sha256(token.encode("utf-8")).hexdigest()

        session = await self.session_repo.find_by_id(session_id)

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
            )

        if session.expires_at < datetime.now() or session.revoked_at:
            self.session_repo.update_session_revoked_at(session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired"
            )

        if old_hashed_token != session.refresh_token_hash:
            await self.session_repo.delete_by_id(session_id)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            )

        new_refresh_token, new_refresh_token_hash = generate_refresh_token()

        await self.session_repo.update_session(
            session_id, {"refresh_token_hash": new_refresh_token_hash}
        )

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh already used"
            )

        new_access_token = generate_access_token(session.user_id)

        await self.session.commit()

        return new_access_token, f"{session_id}.{new_refresh_token}"