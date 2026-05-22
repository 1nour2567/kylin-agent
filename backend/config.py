import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    host: str = os.getenv("HOST", "0.0.0.0")
    port: int = int(os.getenv("PORT", "8008"))
    cors_origins: str = os.getenv("CORS_ORIGINS", "*")

    deepseek_api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    deepseek_base_url: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    deepseek_model: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    agent_mode: str = os.getenv("AGENT_MODE", "mock")
    api_key: str = os.getenv("API_KEY", "")  # empty = auth disabled (dev mode)


settings = Settings()
