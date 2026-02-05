"""Database models and connection."""
from collections.abc import AsyncGenerator
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from app.config import settings


class Base(DeclarativeBase):
    """Base class for all models."""
    pass


class Identity(Base):
    """
    An identity in the system, identified by an Ed25519 public key.

    This represents any entity: agent, human, or system.
    The public_key is the primary identifier - there are no usernames or passwords.
    """
    __tablename__ = "identities"

    public_key: Mapped[str] = mapped_column(
        String(64),  # Ed25519 public key in base64 (44 chars, but allow some margin)
        primary_key=True,
        nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    metadata_json: Mapped[str | None] = mapped_column(
        Text,
        nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )

    # Relationships
    vouches_given: Mapped[list["Vouch"]] = relationship(
        "Vouch",
        foreign_keys="Vouch.voucher_public_key",
        back_populates="voucher"
    )
    vouches_received: Mapped[list["Vouch"]] = relationship(
        "Vouch",
        foreign_keys="Vouch.vouchee_public_key",
        back_populates="vouchee"
    )


class Vouch(Base):
    """
    A vouch from one identity to another.

    This represents a trust relationship: voucher trusts vouchee.
    Vouches can optionally expire and can be revoked.
    Uses composite primary key (voucher_public_key, vouchee_public_key).
    """
    __tablename__ = "vouches"

    voucher_public_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("identities.public_key"),
        primary_key=True,
        nullable=False
    )
    vouchee_public_key: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("identities.public_key"),
        primary_key=True,
        nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False
    )
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )

    # Relationships
    voucher: Mapped["Identity"] = relationship(
        "Identity",
        foreign_keys=[voucher_public_key],
        back_populates="vouches_given"
    )
    vouchee: Mapped["Identity"] = relationship(
        "Identity",
        foreign_keys=[vouchee_public_key],
        back_populates="vouches_received"
    )


# Database engine and session
engine = create_async_engine(settings.database_url, echo=settings.debug)
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get a database session."""
    async with async_session() as session:
        yield session
