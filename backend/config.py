from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    github_token: str = ""
    gemini_api_key: str = ""
    nvd_api_key: str = ""

    app_env: str = "development"
    log_level: str = "INFO"

    github_api_base: str = "https://api.github.com"
    github_request_timeout: int = 30

    osv_api_base: str = "https://api.osv.dev/v1"

    # Risk score component weights —> must sum to 1.0
    weight_change_severity:  float = 0.25
    weight_blast_radius:     float = 0.30
    weight_security_signals: float = 0.25
    weight_dependency_risk:  float = 0.20

    # When a vulnerable function is not reachable -> multiply its CVE score
    # by this factor instead of dropping it —> dep is still present
    reachability_discount: float = 0.15

    gemini_model: str = "gemini-2.5-flash"
    llm_max_retries: int = 3


@lru_cache()
def get_settings() -> Settings:
    return Settings()