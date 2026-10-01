from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DBUSER: str
    PASSWORD: str
    HOST: str
    PORT: int
    DBNAME: str
    DATABASE_URL: str
    JWT_KEY: str
    REFRESH_TOKEN_EXPIRES_AT: str
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI: str
    MAIL_USERNAME: str
    MAIL_PASSWORD: str
    MAIL_FROM: str
    MAIL_PORT: int
    MAIL_SERVER: str = "smtp.yandex.ru"
    BASE_URL: str
    ENDPOINT_URL: str
    ACCESS_KEY: str
    SECRET_KEY: str
    VK_CLIENT_ID: str
    VK_CLIENT_SECRET: str
    VK_REDIRECT_URI: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()