from pydantic_settings import BaseSettings
from functools import lru_cache


class Settings(BaseSettings):
    # Security
    addon_secret: str = "change-me-in-production"  # shared secret with the add-on

    # ML
    model_path: str = "models/classifier.joblib"

    # Anthropic key for LLM-based explanation fallback
    anthropic_api_key: str = ""

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()