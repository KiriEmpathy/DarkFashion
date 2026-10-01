from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
   from app.users.models import User

from sqlalchemy import Enum as SQLEnum, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.auth.types import AuthProvider
from app.database import Base


class Provider(Base):
    __tablename__ = "providers"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    provider: Mapped[AuthProvider] = mapped_column(
        SQLEnum(AuthProvider, name="auth_provider"),
        nullable=False,
    )

    provider_id: Mapped[str] = mapped_column(nullable=False)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="providers",
    )
