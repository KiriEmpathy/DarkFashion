import logging

from fastapi_mail import ConnectionConfig, FastMail, MessageSchema, MessageType
from app.config import settings  # Импортируем наши настройки

# Конфигурация собирается динамически из settings
mail_config = ConnectionConfig(
    MAIL_USERNAME=settings.MAIL_USERNAME,
    MAIL_PASSWORD=settings.MAIL_PASSWORD,
    MAIL_FROM=settings.MAIL_FROM,
    MAIL_PORT=settings.MAIL_PORT,
    MAIL_SERVER=settings.MAIL_SERVER,
    MAIL_STARTTLS=False,
    MAIL_SSL_TLS=True,
    USE_CREDENTIALS=True,
    VALIDATE_CERTS=False
)

class MailService:
    def __init__(self) -> None:
        # Инициализируем клиент fastapi-mail один раз при создании сервиса
        self.fastmail = FastMail(mail_config)

    async def send_verification_email(self, email: str, token: str) -> None:
        """Асинхронная отправка HTML-письма с токеном."""
        verify_url = f"{settings.BASE_URL}/auth/verify?token={token}"
        
        html_content = f"""
        <html>
            <body>
                <h2>Подтверждение регистрации</h2>
                <p>Для активации вашего аккаунта, перейдите по ссылке:</p>
                <a href="{verify_url}">Подтвердить почту</a>
            </body>
        </html>
        """

        message = MessageSchema(
            subject="Подтверждение регистрации",
            recipients=[email],
            body=html_content,
            subtype=MessageType.html
        )

        try:
            # Отправляем письмо
            await self.fastmail.send_message(message)
            return True
        except Exception as mail_error:
            # Важнейший защитный блок: если почта легла, мы пишем ошибку в консоль,
            # но возвращаем False, позволяя UseCase продолжить работу и сохранить юзера!
            logging.error(f"[MAIL ERROR] Не удалось отправить письмо: {mail_error}")
            return False

    async def send_verification_code(self, email: str, code: str) -> bool:
        """Отправка 4-значного кода подтверждения."""
        html_content = f"""
        <html>
            <body style="font-family: Arial, sans-serif; text-align: center;">
                <h2>Подтверждение профиля</h2>
                <p>Ваш одноразовый код верификации:</p>
                <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #4CAF50; margin: 20px 0;">
                    {code}
                </div>
                <p style="color: #999; font-size: 12px;">Код действителен в течение 15 минут.</p>
            </body>
        </html>
        """

        message = MessageSchema(
            subject="Код подтверждения регистрации",
            recipients=[email],
            body=html_content,
            subtype=MessageType.html
        )

        try:
            await self.fastmail.send_message(message)
            return True
        except Exception as e:
            logging.error(f"[MAIL ERROR] Не удалось отправить код: {e}")
            return False