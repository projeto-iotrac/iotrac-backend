from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8443

    TLS_CERT_FILE: str
    TLS_KEY_FILE: str

    DATABASE_URL: str
    AES_KEY_HEX: str
    HMAC_KEY_HEX: str
    JWT_SECRET: str

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()