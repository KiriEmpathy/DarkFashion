import random
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.users.repository import UserRepository
from app.shared.utils.generate_tokens import generate_email_token_for_code, decode_token_ignoring_expiration
from app.mail import MailService

class ResendVerificationCodeUseCase:
    def __init__(
        self,
        user_repository: UserRepository,
        mail_service: MailService,
        session: AsyncSession,
    ):
        self.session = session
        self.user_repository = user_repository
        self.mail_service = mail_service

    async def execute(self, expired_token: str):
        # 1. Декодируем токен (валидность структуры и подписи проверяется внутри функции)
        payload = decode_token_ignoring_expiration(expired_token)
        
        user_id = payload.get("user_id")
        current_attempt = payload.get("attempt", 1)

        # 2. Проверяем пользователя в БД
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, 
                detail="User not found"
            )
        if user.is_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="User already verified"
            )

        # 3. Проверяем лимит (максимум 3 отправки)
        if current_attempt >= 3:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Verification attempts limit exceeded. Please contact support."
            )

        # 4. Генерируем новый код и инкрементируем попытку
        next_attempt = current_attempt + 1
        verification_code = f"{random.randint(1000, 9999)}"
        
        new_verification_token = generate_email_token_for_code(
            user_id=user.id, 
            code=verification_code, 
            attempt=next_attempt
        )

        # 5. Отправляем email
        await self.mail_service.send_verification_code(
            email=user.email, 
            code=verification_code
        )
        
        return new_verification_token
