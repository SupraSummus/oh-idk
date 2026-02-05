"""Use pubkey as primary key

Revision ID: 002
Revises: 001
Create Date: 2026-02-05

"""
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = '002'
down_revision: str | None = '001'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Drop existing tables and recreate with new schema
    # Since this is a breaking change and there's no production data yet,
    # we can drop and recreate cleanly

    # Drop vouches table first (has foreign keys)
    op.drop_table('vouches')

    # Drop identities table
    op.drop_table('identities')

    # Recreate identities table with public_key as primary key
    op.create_table(
        'identities',
        sa.Column('public_key', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.PrimaryKeyConstraint('public_key')
    )

    # Recreate vouches table with composite primary key
    op.create_table(
        'vouches',
        sa.Column('voucher_public_key', sa.String(64), nullable=False),
        sa.Column('vouchee_public_key', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['voucher_public_key'], ['identities.public_key']),
        sa.ForeignKeyConstraint(['vouchee_public_key'], ['identities.public_key']),
        sa.PrimaryKeyConstraint('voucher_public_key', 'vouchee_public_key')
    )

    # Enable Row Level Security on both tables
    op.execute("ALTER TABLE identities ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE vouches ENABLE ROW LEVEL SECURITY")


def downgrade() -> None:
    # Drop new tables
    op.drop_table('vouches')
    op.drop_table('identities')

    # Recreate original tables with UUID primary keys
    op.create_table(
        'identities',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('public_key', sa.String(64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('metadata_json', sa.Text(), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default='true'),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index('ix_identities_public_key', 'identities', ['public_key'], unique=True)

    op.create_table(
        'vouches',
        sa.Column('id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('voucher_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('vouchee_id', postgresql.UUID(as_uuid=False), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked', sa.Boolean(), nullable=False, server_default='false'),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(['voucher_id'], ['identities.id']),
        sa.ForeignKeyConstraint(['vouchee_id'], ['identities.id']),
        sa.PrimaryKeyConstraint('id')
    )

    op.create_index('ix_vouches_voucher_id', 'vouches', ['voucher_id'])
    op.create_index('ix_vouches_vouchee_id', 'vouches', ['vouchee_id'])

    # Enable Row Level Security on both tables
    op.execute("ALTER TABLE identities ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE vouches ENABLE ROW LEVEL SECURITY")
