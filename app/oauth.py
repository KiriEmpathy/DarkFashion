from authlib.integrations.starlette_client import OAuth

from app.config import settings

oauth = OAuth()

oauth.register(
    name="google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    name="vk",
    client_id=settings.VK_CLIENT_ID,
    client_secret=settings.VK_CLIENT_SECRET,
    authorize_url="https://oauth.vk.com/authorize",
    access_token_url="https://vk.com",
    client_kwargs={
        "scope": "email",  # Запрашиваем email пользователя (если привязан)
        "token_endpoint_auth_method": "client_secret_post",
    },
    authorize_params={"v": "5.131"},  # Передаем обязательную для VK версию API
)
