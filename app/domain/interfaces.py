from abc import ABC, abstractmethod

class IStorageService(ABC):
    @abstractmethod
    async def upload_file(self, file_bytes: bytes, filename: str, content_type: str) -> str:
        """Должен загрузить файл и вернуть публичный URL"""
        pass
