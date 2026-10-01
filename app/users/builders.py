from app.auth.schemas.api import UserResponse
from app.users.models import User


def build_user_response(user: User):
    return UserResponse.model_validate(user)
