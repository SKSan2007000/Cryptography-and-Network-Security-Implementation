import os
from pydantic_settings import BaseSettings
from pydantic import ConfigDict


class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql://postgres@127.0.0.1:5433/sentinelcrypt"
    JWT_SECRET: str = "sentinelcrypt-secret-jwt-key-2026-csa5109-implementation-secure"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 10080  # 7 days
    STORAGE_PATH: str = "./data/storage/encrypted-payloads"
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    DEBUG: bool = True

    model_config = ConfigDict(
        env_file=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"),
        extra="allow"
    )


settings = Settings()
