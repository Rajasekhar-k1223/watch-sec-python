"""sync_v1_2_2_final

Revision ID: d40e57ef27bb
Revises: c39d46df26aa
Create Date: 2026-02-03 03:00:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision: str = 'd40e57ef27bb'
down_revision: Union[str, Sequence[str], None] = 'c39d46df26aa'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    conn = op.get_bind()
    inspector = inspect(conn)
    
    # --- Agents Table ---
    existing_agent_cols = [c['name'] for c in inspector.get_columns('Agents')]
    
    agent_cols_to_add = [
        ('SpeechMonitorEnabled', sa.Column('SpeechMonitorEnabled', sa.Boolean(), nullable=True, server_default='0')),
        ('VulnerabilityIntelligenceEnabled', sa.Column('VulnerabilityIntelligenceEnabled', sa.Boolean(), nullable=True, server_default='0')),
    ]
    
    for name, col in agent_cols_to_add:
        if name not in existing_agent_cols:
            op.add_column('Agents', col)
            
    # --- Tenants Table ---
    existing_tenant_cols = [c['name'] for c in inspector.get_columns('Tenants')]
    
    tenant_cols_to_add = [
        ('StripeCustomerId', sa.Column('StripeCustomerId', sa.String(length=255), nullable=True)),
        ('SubscriptionStatus', sa.Column('SubscriptionStatus', sa.String(length=50), nullable=True, server_default='active')),
    ]
    
    for name, col in tenant_cols_to_add:
        if name not in existing_tenant_cols:
            op.add_column('Tenants', col)

def downgrade() -> None:
    op.drop_column('Tenants', 'SubscriptionStatus')
    op.drop_column('Tenants', 'StripeCustomerId')
    op.drop_column('Agents', 'VulnerabilityIntelligenceEnabled')
    op.drop_column('Agents', 'SpeechMonitorEnabled')
