"""Initial migration - identities and vouches

Revision ID: 001
Revises: 
Create Date: 2026-02-04

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create identities table
    op.create_table(
        'identities',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('public_key', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create unique index on public_key
    op.create_index('ix_identities_public_key', 'identities', ['public_key'], unique=True)
    
    # Create vouches table
    op.create_table(
        'vouches',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('voucher_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('vouchee_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=False, default=False),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['voucher_id'], ['identities.id']),
        sa.ForeignKeyConstraint(['vouchee_id'], ['identities.id']),
        sa.PrimaryKeyConstraint('id')
    )
    
    # Create indexes for efficient lookups
    op.create_index('ix_vouches_voucher_id', 'vouches', ['voucher_id'])
    op.create_index('ix_vouches_vouchee_id', 'vouches', ['vouchee_id'])
    
    # Enable Row Level Security on both tables
    op.execute("ALTER TABLE identities ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE vouches ENABLE ROW LEVEL SECURITY")
    
    # Note: RLS policies should be created according to your auth model
    # Example: Allow reading all identities
    # op.execute("""
    #     CREATE POLICY "allow_read_identities" ON identities
    #     FOR SELECT USING (true)
    # """)


def downgrade() -> None:
    op.drop_table('vouches')
    op.drop_table('identities')
