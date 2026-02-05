"""Pydantic schemas for request/response validation."""
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from app.crypto import is_valid_public_key


class RegisterRequest(BaseModel):
    """Request to register a new identity."""
    public_key: str = Field(
        ...,
        description="Base64-encoded Ed25519 public key",
        examples=["AQAB..."]
    )
    metadata: dict[str, str] | None = Field(
        None,
        description="Optional metadata about this identity"
    )

    @field_validator('public_key')
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        if not is_valid_public_key(v):
            raise ValueError('Invalid Ed25519 public key')
        return v


class RegisterResponse(BaseModel):
    """Response after registering an identity."""
    public_key: str
    created_at: datetime


class VouchRequest(BaseModel):
    """Request to vouch for another identity."""
    vouchee_public_key: str = Field(
        ...,
        description="Public key of the identity to vouch for"
    )
    expires_in_days: int | None = Field(
        None,
        description="Number of days until vouch expires (None = no expiry)"
    )

    @field_validator('vouchee_public_key')
    @classmethod
    def validate_vouchee_key(cls, v: str) -> str:
        if not is_valid_public_key(v):
            raise ValueError('Invalid Ed25519 public key')
        return v


class VouchResponse(BaseModel):
    """Response after creating a vouch."""
    voucher_public_key: str
    vouchee_public_key: str
    created_at: datetime
    expires_at: datetime | None


class VouchInfo(BaseModel):
    """Information about a vouch."""
    voucher_public_key: str
    created_at: datetime
    expires_at: datetime | None
    revoked: bool


class TrustResponse(BaseModel):
    """Trust information for an identity."""
    public_key: str
    exists: bool
    trust_score: float
    direct_vouches: int
    vouches: list[VouchInfo]


class VerifyRequest(BaseModel):
    """Request to verify a signature."""
    public_key: str
    message: str
    signature: str

    @field_validator('public_key')
    @classmethod
    def validate_public_key(cls, v: str) -> str:
        if not is_valid_public_key(v):
            raise ValueError('Invalid Ed25519 public key')
        return v


class VerifyResponse(BaseModel):
    """Response to signature verification."""
    valid: bool
    public_key: str


class ErrorResponse(BaseModel):
    """Error response."""
    error: str
    detail: str | None = None
