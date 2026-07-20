import os
try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False

load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    host: str = os.getenv("HOST", "127.0.0.1")
    port: int = int(os.getenv("PORT", "8008"))
    cors_origins: str = os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:8008,http://localhost:8008",
    )
    environment: str = os.getenv("ENVIRONMENT", "development")
    enforce_https: bool = _env_bool("ENFORCE_HTTPS", False)
    tls_certfile: str = os.getenv("TLS_CERTFILE", "")
    tls_keyfile: str = os.getenv("TLS_KEYFILE", "")

    deepseek_api_key: str = os.getenv("DEEPSEEK_API_KEY", "")
    deepseek_base_url: str = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    deepseek_model: str = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

    agent_mode: str = os.getenv("AGENT_MODE", "mock")
    api_key: str = os.getenv("API_KEY", "")  # empty = auth disabled (dev mode)
    allow_anonymous_read: bool = _env_bool("ALLOW_ANONYMOUS_READ", False)
    allow_privileged_confirm: bool = _env_bool("ALLOW_PRIVILEGED_CONFIRM", False)
    restricted_user: str = os.getenv("AGENT_RESTRICTED_USER", "kylin-agent")

    capability_token_secret: str = os.getenv("CAPABILITY_TOKEN_SECRET", "")
    capability_token_ttl_seconds: int = min(
        300, max(1, int(os.getenv("CAPABILITY_TOKEN_TTL_SECONDS", "60")))
    )
    capability_replay_store: str = os.getenv("CAPABILITY_REPLAY_STORE", "")
    ipi_output_mode: str = os.getenv("IPI_OUTPUT_MODE", "block")
    ipi_max_scan_chars: int = max(256, int(os.getenv("IPI_MAX_SCAN_CHARS", "20000")))
    ipi_max_decode_depth: int = max(0, min(4, int(os.getenv("IPI_MAX_DECODE_DEPTH", "2"))))


settings = Settings()
