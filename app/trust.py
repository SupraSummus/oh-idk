"""Trust score calculation (EigenTrust-inspired)."""
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import settings
from app.models import Identity, Vouch


async def get_active_vouches_for(
    session: AsyncSession,
    identity_id: str
) -> list[Vouch]:
    """Get all active (non-revoked, non-expired) vouches for an identity."""
    now = datetime.now(timezone.utc)
    
    query = (
        select(Vouch)
        .where(Vouch.vouchee_id == identity_id)
        .where(Vouch.revoked == False)
        .where(
            (Vouch.expires_at == None) | (Vouch.expires_at > now)
        )
        .options(selectinload(Vouch.voucher))
    )
    
    result = await session.execute(query)
    return list(result.scalars().all())


async def calculate_trust_score(
    session: AsyncSession,
    public_key: str,
    max_depth: int = 3,
    _visited: Optional[set[str]] = None
) -> float:
    """
    Calculate trust score for an identity.
    
    Uses a simplified EigenTrust-inspired algorithm:
    - Direct vouch = 1.0 base trust
    - Transitive trust decays by settings.trust_decay_factor per hop
    - Maximum score capped at settings.max_trust_score
    - Cycles are prevented by tracking visited nodes
    
    Args:
        session: Database session
        public_key: Public key to calculate trust for
        max_depth: Maximum depth of trust traversal
        _visited: Set of already visited public keys (for cycle prevention)
    
    Returns:
        Trust score (0.0 to settings.max_trust_score)
    """
    if _visited is None:
        _visited = set()
    
    if public_key in _visited:
        return 0.0
    
    _visited.add(public_key)
    
    # Find the identity
    query = select(Identity).where(Identity.public_key == public_key)
    result = await session.execute(query)
    identity = result.scalar_one_or_none()
    
    if identity is None:
        return 0.0
    
    # Get active vouches
    vouches = await get_active_vouches_for(session, identity.id)
    
    if not vouches:
        return 0.0
    
    total_score = 0.0
    
    for vouch in vouches:
        # Each direct vouch contributes 1.0
        vouch_score = 1.0
        
        # Add transitive trust from voucher (with decay)
        if max_depth > 0:
            voucher_trust = await calculate_trust_score(
                session,
                vouch.voucher.public_key,
                max_depth=max_depth - 1,
                _visited=_visited
            )
            vouch_score += voucher_trust * settings.trust_decay_factor
        
        total_score += vouch_score
    
    return min(total_score, settings.max_trust_score)


async def get_trust_info(
    session: AsyncSession,
    public_key: str
) -> dict[str, Any]:
    """
    Get detailed trust information for an identity.
    
    Returns:
        Dict with trust score and vouch details
    """
    query = select(Identity).where(Identity.public_key == public_key)
    result = await session.execute(query)
    identity = result.scalar_one_or_none()
    
    if identity is None:
        return {
            "exists": False,
            "trust_score": 0.0,
            "direct_vouches": 0,
            "vouches": []
        }
    
    vouches = await get_active_vouches_for(session, identity.id)
    trust_score = await calculate_trust_score(session, public_key)
    
    vouch_infos: list[dict[str, Any]] = []
    for vouch in vouches:
        vouch_infos.append({
            "id": vouch.id,
            "voucher_public_key": vouch.voucher.public_key,
            "created_at": vouch.created_at,
            "expires_at": vouch.expires_at,
            "revoked": vouch.revoked
        })
    
    return {
        "exists": True,
        "trust_score": trust_score,
        "direct_vouches": len(vouches),
        "vouches": vouch_infos
    }
