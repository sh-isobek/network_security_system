"""add_device_agent_restart_request

Revision ID: 8f3c1d0a5b7e
Revises: 71527755ac21
Create Date: 2026-09-23 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8f3c1d0a5b7e'
down_revision: Union[str, None] = '71527755ac21'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('devices', sa.Column('agent_restart_requested_at', sa.DateTime(), nullable=True))
    op.add_column('devices', sa.Column('agent_restart_requested_by', sa.String(length=100), nullable=True))


def downgrade() -> None:
    op.drop_column('devices', 'agent_restart_requested_by')
    op.drop_column('devices', 'agent_restart_requested_at')
