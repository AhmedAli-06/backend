from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # App
    APP_NAME: str = "ContextShield"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = True

    # Environment
    ENVIRONMENT: str = "development"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://cs_admin:cs_dev_password_2025@localhost:5432/contextshield"
    DATABASE_ECHO: bool = False

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # JWT
    JWT_SECRET_KEY: str = "contextshield-super-secret-key-change-in-production-2025"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480  # 8 hours

    # CORS — accepts JSON array string or comma-separated
    CORS_ORIGINS: str = '["http://localhost:5173", "http://localhost:3000"]'

    # Audit
    HMAC_SECRET: str = "contextshield-hmac-secret-change-in-production"

    # Alerting (Resend)
    RESEND_API_KEY: str = ""
    ALERT_EMAIL: str = ""

    # ML Models
    MODEL_DIR: str = "ml/models"

    # Demo mode
    DEMO_MODE: bool = False

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=(".env.local", ".env.staging", ".env.production", ".env"),
    )


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    print(f"[Config] Running in {settings.ENVIRONMENT} environment")
    print(f"[Config] DEBUG={settings.DEBUG}")
    return settings
