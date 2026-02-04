"""Configuration settings."""
from typing import Any

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings."""

    # Scalingo provides DATABASE_URL in postgresql:// format
    # We need to convert it to postgresql+asyncpg:// for SQLAlchemy async
    database_url: str = "postgresql+asyncpg://localhost:5432/ohidk"
    debug: bool = False
    trust_decay_factor: float = 0.5  # How much trust decays per hop
    max_trust_score: float = 10.0  # Maximum trust score
    vouch_default_ttl_days: int | None = None  # None = no expiry

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        # Convert postgresql:// to postgresql+asyncpg:// for async support
        if self.database_url.startswith("postgresql://"):
            object.__setattr__(
                self,
                "database_url",
                self.database_url.replace("postgresql://", "postgresql+asyncpg://", 1)
            )

    class Config:
        env_file = ".env"


settings: Settings = Settings()
