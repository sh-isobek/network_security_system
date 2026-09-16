"""
Alembic muhit sozlamasi.

MUHIM: sqlalchemy.url alembic.ini'da YOZILMAGAN - bu yerda dinamik
ravishda config/settings.py'dagi DATABASE_URL'dan olinadi (loyihaning
qolgan barcha qismi - db/database.py, run_full_test.py va h.k. - bilan
bir xil yagona manba). Bu shuni anglatadiki:

    export DATABASE_URL="postgresql://user:pass@host:5432/db"
    alembic upgrade head

kod o'zgarishisiz PostgreSQL'ga, aks holda (standart) SQLite'ga ishlaydi.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

from db.models import Base
from config.settings import DATABASE_URL

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

config.set_main_option("sqlalchemy.url", DATABASE_URL)

# `db/models.py`dagi barcha jadvallar - autogenerate shu bilan solishtiradi.
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
