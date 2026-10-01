import uuid
import aioboto3
from app.domain.interfaces import IStorageService

class SupabaseS3StorageService(IStorageService):
    def __init__(self, endpoint_url: str, region: str, access_key: str, secret_key: str, bucket_name: str):
        self.endpoint_url = endpoint_url
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.bucket_name = bucket_name
        # Выделяем базовый URL для публичного скачивания (до /storage/v1/s3)
        self.base_project_url = endpoint_url.replace("/storage/v1/s3", "")

    async def upload_file(self, file_bytes: bytes, filename: str, content_type: str) -> str:
        file_extension = filename.split(".")[-1] if "." in filename else "jpg"
        unique_filename = f"{uuid.uuid4()}.{file_extension}"
        storage_path = f"avatars/{unique_filename}"

        # Создаем асинхронную сессию aioboto3
        session = aioboto3.Session()
        async with session.client(
            's3',
            endpoint_url=self.endpoint_url,
            region_name=self.region,
            aws_access_key_id=self.access_key,
            aws_secret_access_key=self.secret_key
        ) as s3_client:
            
            # Асинхронно загружаем байты в бакет
            await s3_client.put_object(
                Bucket=self.bucket_name,
                Key=storage_path,
                Body=file_bytes,
                ContentType=content_type
            )
        
        # Формируем и возвращаем публичный URL для сохранения в SQLAlchemy
        return f"{self.base_project_url}/storage/v1/object/public/{self.bucket_name}/{storage_path}"
