from sqlalchemy import delete, select, update
from sqlalchemy.orm import joinedload
from sqlalchemy.ext.asyncio import AsyncSession

from app.users.models import User


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def find_by_id(self, user_id: str) -> User | None:
            stmt = select(User).where(User.id == int(user_id))
            result = await self.session.execute(stmt)
            return result.scalar_one_or_none()
    
    async def find_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def create(self, name: str, email: str, password_hash: str|None) -> User:
        user = User(
            name=name,
            email=email,
            password_hash=password_hash,
        )

        self.session.add(user)
        await self.session.flush()

        return user

    async def delete_by_ids(self, user_ids: list[int]) -> int:
        stmt = delete(User).where(User.id.in_(user_ids))
        result = await self.session.execute(stmt)
        await self.session.flush() 
        
        return result.rowcount or 0

    async def mark_as_verified(self, user_id: int) -> None:
        stmt = (
             update(User)
             .where(User.id == user_id)
             .values(is_verified = True)
        )
        await self.session.execute(stmt)