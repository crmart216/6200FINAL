from sqlalchemy import ForeignKey, LargeBinary, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


class KeyPackage(Base):
    __tablename__: str = "key_packages"

    package_id: Mapped[str] = mapped_column(Text, primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(Text, ForeignKey("users.user_id"))
    credential: Mapped[bytes] = mapped_column(LargeBinary)
    init_public_key: Mapped[bytes] = mapped_column(LargeBinary)
    leaf_public_key: Mapped[bytes] = mapped_column(LargeBinary)
    signing_public_key: Mapped[bytes] = mapped_column(LargeBinary)
    signature: Mapped[bytes] = mapped_column(LargeBinary)