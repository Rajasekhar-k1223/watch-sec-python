"""Add TrustedDomainsJson to Tenants

Revision ID: f1a2b3c4d5e6
Revises: d2a4c065a8e0
Create Date: 2026-01-05 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f1a2b3c4d5e6'
down_revision: Union[str, Sequence[str], None] = 'a45a305a0c74'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Use batch_alter_table for SQLite compatibility if needed, but safe for MySQL too
    with op.batch_alter_table('Tenants', schema=None) as batch_op:
        batch_op.add_column(sa.Column('TrustedDomainsJson', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('TrustedIPsJson', sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('Tenants', schema=None) as batch_op:
        batch_op.drop_column('TrustedIPsJson')
        batch_op.drop_column('TrustedDomainsJson')
