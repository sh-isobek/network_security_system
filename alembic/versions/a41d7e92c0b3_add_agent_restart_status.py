"""add_agent_restart_status

Revision ID: a41d7e92c0b3
Revises: 8f3c1d0a5b7e
Create Date: 2026-09-24 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'a41d7e92c0b3'
down_revision: Union[str, None] = '8f3c1d0a5b7e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_NEW_COLUMNS = [
    ('agent_restart_status', sa.String(length=20)),
    ('agent_restart_message', sa.String(length=500)),
    ('agent_restart_picked_up_at', sa.DateTime()),
    ('agent_restart_finished_at', sa.DateTime()),
]


def upgrade() -> None:
    # Idempotent: `_sync_missing_columns()` (init_db) ustunni Alembic'dan OLDIN
    # qo'shib qo'ygan bo'lishi mumkin (konteyner yangi kod bilan avval ko'tarilsa).
    existing = {c["name"] for c in sa.inspect(op.get_bind()).get_columns("devices")}
    for name, coltype in _NEW_COLUMNS:
        if name not in existing:
            op.add_column('devices', sa.Column(name, coltype, nullable=True))
    # Eski (holat-kuzatuvi yo'q) versiyada qo'yilgan, hech qachon bajarilmagan
    # so'rovlar: yangi mantiqda ular darhol "muvaffaqiyatsiz" alert berib yubormasligi uchun tozalanadi.
    op.execute("UPDATE devices SET agent_restart_requested_at = NULL, agent_restart_requested_by = NULL "
               "WHERE agent_restart_requested_at IS NOT NULL AND agent_restart_status IS NULL")


def downgrade() -> None:
    for name, _ in reversed(_NEW_COLUMNS):
        op.drop_column('devices', name)
