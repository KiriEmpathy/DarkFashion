from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


class SignUpRequest(BaseModel):
    name: str
    password: str
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str):
        return value.strip().lower()

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str):
        return value.strip().lower()

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    email: str
    id: int
    is_verified: bool

class VerifyCodeRequest(BaseModel):
    code: str

class ResendVerificationRequest(BaseModel):
    expired_token: str = Field(..., description="Истекший verification_token, полученный при регистрации или прошлой отправке")
