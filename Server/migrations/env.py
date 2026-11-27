from alembic import context
from sqlalchemy import Connection

from Server import models
from Server.database import Base, get_engine

target_metadata = Base.metadata  # Importing models registers the seven tables.
__all__ = ["models", "target_metadata"]


def migrate(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    context.configure(
        dialect_name="postgresql",
        target_metadata=target_metadata,
        literal_binds=True,
    )
    with context.begin_transaction():
        context.run_migrations()
else:
    supplied = context.config.attributes.get("connection")
    if isinstance(supplied, Connection):
        migrate(supplied)
    else:
        with get_engine().connect() as connection:
            migrate(connection)