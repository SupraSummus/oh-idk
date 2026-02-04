"""Configuration settings."""
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""
    
    database_url: str = "postgresql+asyncpg://localhost:5432/ohidk"
    debug: bool = False
    trust_decay_factor: float = 0.5  # How much trust decays per hop
    max_trust_score: float = 10.0  # Maximum trust score
    vouch_default_ttl_days: int | None = None  # None = no expiry
    
    class Config:
        env_file = ".env"


settings = Settings()
