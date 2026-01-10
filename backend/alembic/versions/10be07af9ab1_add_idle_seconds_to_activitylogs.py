"""add_idle_seconds_to_activitylogs

Revision ID: 10be07af9ab1
Revises: 67ae673c1df9
Create Date: 2026-01-10 10:59:52.188800

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '10be07af9ab1'
down_revision: Union[str, Sequence[str], None] = '67ae673c1df9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('ActivityLogs', sa.Column('IdleSeconds', sa.Float(), nullable=True, default=0.0))
    op.add_column('ActivityLogs', sa.Column('Category', sa.String(length=50), nullable=True, default="Neutral"))
    op.add_column('ActivityLogs', sa.Column('ProductivityScore', sa.Float(), nullable=True, default=0.0))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('ActivityLogs', 'ProductivityScore')
    op.drop_column('ActivityLogs', 'Category')
    op.drop_column('ActivityLogs', 'IdleSeconds')
