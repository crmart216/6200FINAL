from sqlalchemy import LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from Server.core.database import Base


class User(Base):
    __tablename__: str = "users"

    user_id: Mapped[str] = mapped_column(Text, primary_key=True)
    display_name: Mapped[str] = mapped_column(Text)
    websocket_url: Mapped[str] = mapped_column(Text)
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary)