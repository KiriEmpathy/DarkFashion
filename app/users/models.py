from datetime import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.sessions.models import Session
    from app.providers.models import Provider

from sqlalchemy import String, func

from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(50), nullable=False)
    email: Mapped[str] = mapped_column(nullable=False)
    password_hash: Mapped[str | None] = mapped_column(nullable=True)
    is_verified: Mapped[bool] = mapped_column(default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(),nullable=False)

    sessions: Mapped[list["Session"]] = relationship(
        "Session",
        back_populates="user",
        cascade="all, delete-orphan",
    )

    providers: Mapped[list["Provider"]] = relationship(
        "Provider",
        back_populates="user",
        cascade="all, delete-orphan",
    )


