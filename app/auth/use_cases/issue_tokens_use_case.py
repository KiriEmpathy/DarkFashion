from fastapi import Request
from user_agents import parse

from app.auth.repository.session_repo import SessionRepository
from app.users.models import User
from app.shared.utils.generate_tokens import (
    generate_access_token,
    generate_refresh_token,
)


class IssueTokensUseCase:
    def __init__(self, session_repository: SessionRepository):
        self.session_repository = session_repository

    async def execute(self, user: User, request: Request):
        ua = parse(request.headers.get("user-agent", ""))

        device = ua.device.family if not ua.is_pc else "desktop"
        platform = ua.os.family or "unknown"

        token, hashed_token = generate_refresh_token()

        ip = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or request.client.host
            or "unknown"
        )

        await self.session_repository.reject_sessions(user.id)

        create_session = await self.session_repository.create_session(
            user.id, ip, device, platform, hashed_token, ua
        )

        access_token = generate_access_token(user.id)

        return access_token, f"{create_session.id}.{token}"