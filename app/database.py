from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import async_sessionmaker as SqlAlchemySession
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings



class Base(DeclarativeBase):
    pass

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=True,
    pool_pre_ping=True,
    #connect_args={"ssl": "require"},
)

AsyncSession = SqlAlchemySession(
    bind=engine,
    expire_on_commit=False,
)


async def get_session() -> AsyncGenerator[SqlAlchemySession, None]:
    async with AsyncSession() as session:
        yield session