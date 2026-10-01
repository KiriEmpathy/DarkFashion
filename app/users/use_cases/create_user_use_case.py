from fastapi.exceptions import HTTPException
from pydantic import EmailStr

from app.users.models import User
from app.shared.utils.hashing import hash_password
from app.users.repository import UserRepository


class CreateUserUseCase:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def execute(self, name: str, email: EmailStr, password: str | None = None) -> User:
        if password and not password.strip():
                raise HTTPException(400, detail="Неверный формат пароля")

        user = await self.user_repository.find_by_email(email)
        if user:
            raise HTTPException(409, detail="Пользователь с таким Email уже существует")
        password_hash = hash_password(password)
        user = await self.user_repository.create(
            name=name, email=email, password_hash=password_hash
        )
        return user
