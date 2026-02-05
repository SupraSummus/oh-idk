"""Main FastAPI application."""
import json
from datetime import UTC, datetime, timedelta
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import verify_auth_headers
from app.config import settings
from app.crypto import is_valid_public_key, verify_signature
from app.models import Identity, Vouch, get_db
from app.schemas import (
    ErrorResponse,
    RegisterRequest,
    RegisterResponse,
    TrustResponse,
    VerifyRequest,
    VerifyResponse,
    VouchInfo,
    VouchRequest,
    VouchResponse,
)
from app.trust import get_trust_info

# Configure rate limiter with headers enabled
limiter = Limiter(key_func=get_remote_address, headers_enabled=True)

app = FastAPI(
    title="oh-idk",
    description="Agent Identity/SSO Service based on Web of Trust",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]


@app.get("/")
async def root() -> dict[str, str]:
    """Root endpoint."""
    return {"status": "ok", "service": "oh-idk"}


@app.get("/health")
async def health_check() -> dict[str, str]:
    """
    Health check endpoint for monitoring.

    Returns service status for load balancers and monitoring systems.
    """
    return {"status": "healthy", "service": "oh-idk", "version": "0.1.0"}


@app.post(
    "/register",
    response_model=RegisterResponse,
    responses={400: {"model": ErrorResponse}, 409: {"model": ErrorResponse}}
)
@limiter.limit("10/minute")
async def register(
    request: Request,
    response: Response,
    body: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
) -> RegisterResponse:
    """
    Register a new identity.

    Anyone can register a public key. The key becomes the identity.
    No authentication required - you just need to have a valid Ed25519 key.

    Rate limit: 10 requests per minute per IP address.
    """
    # Check if key already exists
    query = select(Identity).where(Identity.public_key == body.public_key)
    result = await db.execute(query)
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=409, detail="Public key already registered")

    # Create new identity
    identity = Identity(
        public_key=body.public_key,
        metadata_json=json.dumps(body.metadata) if body.metadata else None
    )

    db.add(identity)
    await db.commit()
    await db.refresh(identity)

    return RegisterResponse(
        public_key=identity.public_key,
        created_at=identity.created_at
    )


@app.post(
    "/vouch",
    response_model=VouchResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}}
)
@limiter.limit("30/minute")
async def vouch(
    request: Request,
    response: Response,
    body: VouchRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    public_key: Annotated[str, Depends(verify_auth_headers)]
) -> VouchResponse:
    """
    Vouch for another identity.

    Requires authentication (signed request).
    Both voucher and vouchee must be registered.

    Rate limit: 30 requests per minute per IP address.
    """
    # Get voucher identity
    voucher_query = select(Identity).where(Identity.public_key == public_key)
    result = await db.execute(voucher_query)
    voucher = result.scalar_one_or_none()

    if not voucher:
        raise HTTPException(status_code=404, detail="Voucher not registered")

    # Get vouchee identity
    vouchee_query = select(Identity).where(Identity.public_key == body.vouchee_public_key)
    result = await db.execute(vouchee_query)
    vouchee = result.scalar_one_or_none()

    if not vouchee:
        raise HTTPException(status_code=404, detail="Vouchee not registered")

    # Can't vouch for yourself
    if voucher.public_key == vouchee.public_key:
        raise HTTPException(status_code=400, detail="Cannot vouch for yourself")

    # Check if vouch already exists
    existing_query = (
        select(Vouch)
        .where(Vouch.voucher_public_key == voucher.public_key)
        .where(Vouch.vouchee_public_key == vouchee.public_key)
        .where(Vouch.revoked.is_(False))
    )
    result = await db.execute(existing_query)
    existing = result.scalar_one_or_none()

    if existing:
        raise HTTPException(status_code=409, detail="Active vouch already exists")

    # Calculate expiry
    expires_at = None
    if body.expires_in_days:
        expires_at = datetime.now(UTC) + timedelta(days=body.expires_in_days)
    elif settings.vouch_default_ttl_days:
        expires_at = datetime.now(UTC) + timedelta(days=settings.vouch_default_ttl_days)

    # Create vouch
    vouch = Vouch(
        voucher_public_key=voucher.public_key,
        vouchee_public_key=vouchee.public_key,
        expires_at=expires_at
    )

    db.add(vouch)
    await db.commit()
    await db.refresh(vouch)

    return VouchResponse(
        voucher_public_key=public_key,
        vouchee_public_key=body.vouchee_public_key,
        created_at=vouch.created_at,
        expires_at=vouch.expires_at
    )


@app.get(
    "/trust/{public_key}",
    response_model=TrustResponse
)
@limiter.limit("100/minute")
async def get_trust(
    request: Request,
    response: Response,
    public_key: str,
    db: Annotated[AsyncSession, Depends(get_db)]
) -> TrustResponse:
    """
    Get trust information for an identity.

    Returns trust score and list of vouches.
    No authentication required - trust info is public.

    Rate limit: 100 requests per minute per IP address.
    """
    if not is_valid_public_key(public_key):
        raise HTTPException(status_code=400, detail="Invalid public key format")

    trust_info = await get_trust_info(db, public_key)

    vouches = [
        VouchInfo(
            voucher_public_key=v["voucher_public_key"],
            created_at=v["created_at"],
            expires_at=v["expires_at"],
            revoked=v["revoked"]
        )
        for v in trust_info["vouches"]
    ]

    return TrustResponse(
        public_key=public_key,
        exists=trust_info["exists"],
        trust_score=trust_info["trust_score"],
        direct_vouches=trust_info["direct_vouches"],
        vouches=vouches
    )


@app.post(
    "/verify",
    response_model=VerifyResponse
)
@limiter.limit("100/minute")
async def verify(
    request: Request,
    response: Response,
    body: VerifyRequest
) -> VerifyResponse:
    """
    Verify a signature.

    This is a utility endpoint - no database access, just cryptographic verification.
    Useful for other services to verify signatures without their own crypto implementation.

    Rate limit: 100 requests per minute per IP address.
    """
    is_valid = verify_signature(
        public_key_b64=body.public_key,
        message=body.message,
        signature_b64=body.signature
    )

    return VerifyResponse(
        valid=is_valid,
        public_key=body.public_key
    )


@app.delete(
    "/vouch",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}}
)
@limiter.limit("30/minute")
async def revoke_vouch(
    request: Request,
    response: Response,
    voucher_public_key: str,
    vouchee_public_key: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    public_key: Annotated[str, Depends(verify_auth_headers)]
) -> dict[str, str]:
    """
    Revoke a vouch.

    Only the voucher can revoke their own vouch.
    Requires authentication (signed request).

    Rate limit: 30 requests per minute per IP address.

    Query Parameters:
        voucher_public_key: Public key of the voucher
        vouchee_public_key: Public key of the vouchee
    """
    # Get the vouch
    query = (
        select(Vouch)
        .where(Vouch.voucher_public_key == voucher_public_key)
        .where(Vouch.vouchee_public_key == vouchee_public_key)
    )
    result = await db.execute(query)
    vouch = result.scalar_one_or_none()

    if not vouch:
        raise HTTPException(status_code=404, detail="Vouch not found")

    # Check authorization
    if voucher_public_key != public_key:
        raise HTTPException(status_code=401, detail="Not authorized to revoke this vouch")

    if vouch.revoked:
        raise HTTPException(status_code=400, detail="Vouch already revoked")

    # Revoke
    vouch.revoked = True
    vouch.revoked_at = datetime.now(UTC)
    await db.commit()

    return {
        "status": "revoked",
        "voucher_public_key": voucher_public_key,
        "vouchee_public_key": vouchee_public_key
    }
