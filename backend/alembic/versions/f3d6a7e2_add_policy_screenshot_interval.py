"""add policy screenshot interval

Revision ID: f3d6a7e2
Revises: e51f6801
Create Date: 2026-03-24 15:15:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f3d6a7e2'
down_revision = 'e51f6801'
branch_labels = None
depends_on = None


def upgrade():
    # Add ScreenshotInterval column to Policies table
    op.add_column('Policies', sa.Column('ScreenshotInterval', sa.Integer(), nullable=True, server_default='60'))


def downgrade():
    op.drop_column('Policies', 'ScreenshotInterval')
