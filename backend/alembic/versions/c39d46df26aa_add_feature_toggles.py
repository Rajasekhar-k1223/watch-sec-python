"""add_feature_toggles_and_json_fields

Revision ID: c39d46df26aa
Revises: b28c35cf25ff
Create Date: 2026-02-02 14:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'c39d46df26aa'
down_revision: Union[str, Sequence[str], None] = 'b28c35cf25ff'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    from sqlalchemy import inspect
    inspector = inspect(conn)
    existing_columns = [c['name'] for c in inspector.get_columns('Agents')]

    cols_to_add = [
        ('ActivityMonitorEnabled', sa.Column('ActivityMonitorEnabled', sa.Boolean(), nullable=True, server_default='1')),
        ('KeyloggerEnabled', sa.Column('KeyloggerEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('ClipboardMonitorEnabled', sa.Column('ClipboardMonitorEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('AppBlockerEnabled', sa.Column('AppBlockerEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('BrowserEnforcerEnabled', sa.Column('BrowserEnforcerEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('PrinterMonitorEnabled', sa.Column('PrinterMonitorEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('ShadowMonitorEnabled', sa.Column('ShadowMonitorEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('LiveStreamEnabled', sa.Column('LiveStreamEnabled', sa.Boolean(), nullable=True, server_default='1')),
        ('RemoteShellEnabled', sa.Column('RemoteShellEnabled', sa.Boolean(), nullable=True, server_default='1')),
        ('MailMonitorEnabled', sa.Column('MailMonitorEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('IsPendingUninstall', sa.Column('IsPendingUninstall', sa.Boolean(), nullable=True, server_default='0')),
        ('BlockedAppsJson', sa.Column('BlockedAppsJson', sa.Text(), nullable=True)),
        ('ShadowPathsJson', sa.Column('ShadowPathsJson', sa.Text(), nullable=True))
    ]

    for name, col in cols_to_add:
        if name not in existing_columns:
            op.add_column('Agents', col)

def downgrade() -> None:
    op.drop_column('Agents', 'ShadowPathsJson')
    op.drop_column('Agents', 'BlockedAppsJson')
    op.drop_column('Agents', 'MailMonitorEnabled')
    op.drop_column('Agents', 'RemoteShellEnabled')
    op.drop_column('Agents', 'LiveStreamEnabled')
    op.drop_column('Agents', 'ShadowMonitorEnabled')
    op.drop_column('Agents', 'PrinterMonitorEnabled')
    op.drop_column('Agents', 'BrowserEnforcerEnabled')
    op.drop_column('Agents', 'AppBlockerEnabled')
    op.drop_column('Agents', 'ClipboardMonitorEnabled')
    op.drop_column('Agents', 'KeyloggerEnabled')
    op.drop_column('Agents', 'ActivityMonitorEnabled')
