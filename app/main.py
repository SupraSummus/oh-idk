"""Main FastAPI application."""
import json
from datetime import datetime, timedelta, timezone
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
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

app = FastAPI(
    title="oh-idk",
    description="Agent Identity/SSO Service based on Web of Trust",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc"
)


@app.get("/")
async def root() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "service": "oh-idk"}


@app.post(
    "/register",
    response_model=RegisterResponse,
    responses={400: {"model": ErrorResponse}, 409: {"model": ErrorResponse}}
)
async def register(
    request: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)]
) -> RegisterResponse:
    """
    Register a new identity.
    
    Anyone can register a public key. The key becomes the identity.
    No authentication required - you just need to have a valid Ed25519 key.
    """
    # Check if key already exists
    query = select(Identity).where(Identity.public_key == request.public_key)
    result = await db.execute(query)
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(status_code=409, detail="Public key already registered")
    
    # Create new identity
    identity = Identity(
        public_key=request.public_key,
        metadata_json=json.dumps(request.metadata) if request.metadata else None
    )
    
    db.add(identity)
    await db.commit()
    await db.refresh(identity)
    
    return RegisterResponse(
        id=identity.id,
        public_key=identity.public_key,
        created_at=identity.created_at
    )


@app.post(
    "/vouch",
    response_model=VouchResponse,
    responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}}
)
async def vouch(
    request: VouchRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    public_key: Annotated[str, Depends(verify_auth_headers)]
) -> VouchResponse:
    """
    Vouch for another identity.
    
    Requires authentication (signed request).
    Both voucher and vouchee must be registered.
    """
    # Get voucher identity
    voucher_query = select(Identity).where(Identity.public_key == public_key)
    result = await db.execute(voucher_query)
    voucher = result.scalar_one_or_none()
    
    if not voucher:
        raise HTTPException(status_code=404, detail="Voucher not registered")
    
    # Get vouchee identity
    vouchee_query = select(Identity).where(Identity.public_key == request.vouchee_public_key)
    result = await db.execute(vouchee_query)
    vouchee = result.scalar_one_or_none()
    
    if not vouchee:
        raise HTTPException(status_code=404, detail="Vouchee not registered")
    
    # Can't vouch for yourself
    if voucher.id == vouchee.id:
        raise HTTPException(status_code=400, detail="Cannot vouch for yourself")
    
    # Check if vouch already exists
    existing_query = (
        select(Vouch)
        .where(Vouch.voucher_id == voucher.id)
        .where(Vouch.vouchee_id == vouchee.id)
        .where(Vouch.revoked == False)
    )
    result = await db.execute(existing_query)
    existing = result.scalar_one_or_none()
    
    if existing:
        raise HTTPException(status_code=409, detail="Active vouch already exists")
    
    # Calculate expiry
    expires_at = None
    if request.expires_in_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=request.expires_in_days)
    elif settings.vouch_default_ttl_days:
        expires_at = datetime.now(timezone.utc) + timedelta(days=settings.vouch_default_ttl_days)
    
    # Create vouch
    vouch = Vouch(
        voucher_id=voucher.id,
        vouchee_id=vouchee.id,
        expires_at=expires_at
    )
    
    db.add(vouch)
    await db.commit()
    await db.refresh(vouch)
    
    return VouchResponse(
        id=vouch.id,
        voucher_public_key=public_key,
        vouchee_public_key=request.vouchee_public_key,
        created_at=vouch.created_at,
        expires_at=vouch.expires_at
    )


@app.get(
    "/trust/{public_key}",
    response_model=TrustResponse
)
async def get_trust(
    public_key: str,
    db: Annotated[AsyncSession, Depends(get_db)]
) -> TrustResponse:
    """
    Get trust information for an identity.
    
    Returns trust score and list of vouches.
    No authentication required - trust info is public.
    """
    if not is_valid_public_key(public_key):
        raise HTTPException(status_code=400, detail="Invalid public key format")
    
    trust_info = await get_trust_info(db, public_key)
    
    vouches = [
        VouchInfo(
            id=v["id"],
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
async def verify(
    request: VerifyRequest
) -> VerifyResponse:
    """
    Verify a signature.
    
    This is a utility endpoint - no database access, just cryptographic verification.
    Useful for other services to verify signatures without their own crypto implementation.
    """
    is_valid = verify_signature(
        public_key_b64=request.public_key,
        message=request.message,
        signature_b64=request.signature
    )
    
    return VerifyResponse(
        valid=is_valid,
        public_key=request.public_key
    )


@app.delete(
    "/vouch/{vouch_id}",
    responses={401: {"model": ErrorResponse}, 404: {"model": ErrorResponse}}
)
async def revoke_vouch(
    vouch_id: str,
    db: Annotated[AsyncSession, Depends(get_db)],
    public_key: Annotated[str, Depends(verify_auth_headers)]
) -> dict[str, str]:
    """
    Revoke a vouch.
    
    Only the voucher can revoke their own vouch.
    Requires authentication (signed request).
    """
    # Get the vouch
    query = select(Vouch).where(Vouch.id == vouch_id)
    result = await db.execute(query)
    vouch = result.scalar_one_or_none()
    
    if not vouch:
        raise HTTPException(status_code=404, detail="Vouch not found")
    
    # Get voucher identity
    voucher_query = select(Identity).where(Identity.id == vouch.voucher_id)
    result = await db.execute(voucher_query)
    voucher = result.scalar_one_or_none()
    
    if not voucher or voucher.public_key != public_key:
        raise HTTPException(status_code=401, detail="Not authorized to revoke this vouch")
    
    if vouch.revoked:
        raise HTTPException(status_code=400, detail="Vouch already revoked")
    
    # Revoke
    vouch.revoked = True
    vouch.revoked_at = datetime.now(timezone.utc)
    await db.commit()
    
    return {"status": "revoked", "vouch_id": vouch_id}
