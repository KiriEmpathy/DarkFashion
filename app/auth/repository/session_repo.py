from datetime import datetime, timedelta

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.sessions.models import Session


class SessionRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def update_session(self, session_id: str, values_to_update: dict):
        stmt = update(Session).where(Session.id == int(session_id), Session.revoked_at == None).values(**values_to_update).returning(Session.id)
        result = await self.session.execute(stmt)

        return result.scalar_one_or_none()

    async def update_session_revoked_at(self, session_id: str) -> Session | None:
        stmt = update(Session).where(Session.id == int(session_id)).values(revoked_at=func.now())
        result = await self.session.execute(stmt)

        return result.scalar_one_or_none()

    async def find_by_id(self, session_id: str) -> Session | None:
        stmt = select(Session).where(Session.id == int(session_id))
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def find_by_refresh_token_hash(self, refresh_token_hash: str) -> Session | None:
            stmt = select(Session).where(Session.refresh_token_hash == refresh_token_hash)
            result = await self.session.execute(stmt)
            return result.scalar_one_or_none()

    async def delete_by_id(self, session_id: str):
        stmt = delete(Session).where(Session.id == int(session_id))
        await self.session.execute(stmt)

    async def delete_by_refresh_token_hash(self, refresh_token_hash: str):
        stmt = delete(Session).where(Session.refresh_token_hash == refresh_token_hash)
        await self.session.execute(stmt)

    async def reject_sessions(self, user_id):
        subquery = (
            select(Session.id)
            .where(Session.user_id == user_id)
            .order_by(Session.created_at.asc())
            .offset(4)
        )

        stmt = delete(Session).where(Session.id.in_(subquery))

        await self.session.execute(stmt)
        await self.session.flush()

    async def create_session(
        self, user_id, ip, device, platform, refresh_token_hash, user_agent
    ):
        session = Session(
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            ip=ip,
            user_agent=str(user_agent),
            last_used_at=datetime.now(),
            expires_at=datetime.now()
            + timedelta(milliseconds=int(eval(settings.REFRESH_TOKEN_EXPIRES_AT))),
        )
        self.session.add(session)
        await self.session.flush()

        return session