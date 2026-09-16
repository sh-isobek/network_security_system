"""add_missing_api_tokens_agent_hostname_index

Revision ID: 79ad4a5404a6
Revises: c15ffeb890b8
Create Date: 2026-09-16 08:59:00.507269

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


# revision identifiers, used by Alembic.
revision: str = '79ad4a5404a6'
down_revision: Union[str, None] = 'c15ffeb890b8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # MUHIM: bu migratsiya ATAYLAB idempotent qilingan. U dastlab FAQAT
    # production bazasidagi haqiqiy drift'ni (`_sync_missing_columns()`
    # hech qachon indeks qo'shmagani sabab yetishmayotgan indeks) yopish
    # uchun yozilgan edi. Lekin BO'SH (yangi) bazada baseline migratsiya
    # (`c15ffeb890b8`) bu indeksni MODEL orqali ALLAQACHON yaratadi -
    # shuning uchun shartsiz `op.create_index()` yangi o'rnatishlarda
    # "index already exists" xatosi bilan muvaffaqiyatsiz bo'lardi (bu
    # haqiqiy, run_full_test.py'ning #92 testi orqali topilgan bo'shliq).
    conn = op.get_bind()
    existing = {ix["name"] for ix in inspect(conn).get_indexes("api_tokens")}
    if "ix_api_tokens_agent_hostname" not in existing:
        op.create_index(op.f('ix_api_tokens_agent_hostname'), 'api_tokens', ['agent_hostname'], unique=False)


def downgrade() -> None:
    conn = op.get_bind()
    existing = {ix["name"] for ix in inspect(conn).get_indexes("api_tokens")}
    if "ix_api_tokens_agent_hostname" in existing:
        op.drop_index(op.f('ix_api_tokens_agent_hostname'), table_name='api_tokens')
