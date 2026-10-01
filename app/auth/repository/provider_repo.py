from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.providers.models import Provider
from app.users.models import User


class ProviderRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def find_by_provider_id(self, provider, provider_id):
        stmt = select(Provider).where(
            Provider.provider_id == provider_id, Provider.provider == provider
        )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
    
    async def create_provider(self, user_id, provider, provider_id):
        provider_ex = Provider(provider=provider, user_id=user_id, provider_id=provider_id)
        self.session.add(provider_ex)
        await self.session.flush()

        return provider_ex

    async def find_user_by_provider(self, provider: str, provider_id: str):
            stmt = (
                select(User)
                .join(Provider, User.id == Provider.user_id)
                .where(
                    Provider.provider == provider,
                    Provider.provider_id == provider_id
                )
            )

            result = await self.session.execute(stmt)

            return result.scalar_one_or_none()