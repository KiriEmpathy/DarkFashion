from fastapi import HTTPException, status
from jwt import ExpiredSignatureError, InvalidTokenError, decode

from app.config import settings
from app.mail import MailService
from app.users.repository import UserRepository


class VerifyEmailUseCase:
    def __init__(self, user_repository: UserRepository, mail_service: MailService):
        self.user_repo = user_repository
        self.mail_service = mail_service

    async def execute(self, verification_code: str, token: str):
        try:
            payload = decode(token, key=settings.JWT_KEY, algorithms=['HS256'])
            user_id: str = payload.get("sub")
            code: str = payload.get("code")

            if user_id is None or code != verification_code:
                raise InvalidTokenError()
        except ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "VERIFICATION_LINK_EXPIRED", "message": "Verification link has expired"}
            )
        except InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"code": "INVALID_VERIFICATION_TOKEN", "message": "Invalid verification token"}
            )

        user = await self.user_repo.find_by_id(user_id=user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"code": "USER_NOT_FOUND", "message": "User not found"}
            )
        await self.user_repo.mark_as_verified(user.id)

        await self.user_repo.session.commit()