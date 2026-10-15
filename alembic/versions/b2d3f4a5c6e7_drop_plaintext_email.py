"""drop plaintext email

Revision ID: b2d3f4a5c6e7
Revises: a1c2e3f4b5d6
Create Date: 2026-10-15 18:05:00

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b2d3f4a5c6e7'
down_revision: Union[str, None] = 'a1c2e3f4b5d6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Запускати лише після python -m scripts.migrate_encrypt
    left = op.get_bind().execute(sa.text(
        "SELECT COUNT(*) FROM users WHERE email IS NOT NULL AND encrypted_email IS NULL"
    )).scalar()
    if left:
        raise RuntimeError(
            f"{left} користувачів без encrypted_email: спершу python -m scripts.migrate_encrypt"
        )
    with op.batch_alter_table("users") as batch:
        batch.drop_index("ix_users_email")
        batch.drop_column("email")


def downgrade() -> None:
    # Відкритий email не відновлюється — лише порожня колонка
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("email", sa.String(100), nullable=True))
