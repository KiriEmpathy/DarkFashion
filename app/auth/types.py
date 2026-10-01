from enum import Enum

class AuthProvider(str, Enum):
    GOOGLE = "google"
    VK = "vk"
    PASSWORD = "password"