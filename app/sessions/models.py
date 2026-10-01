from __future__ import annotations
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.users.models import User

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address

from sqlalchemy import ForeignKey, Integer, func
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    refresh_token_hash: Mapped[str] = mapped_column()
    expires_at: Mapped[datetime] = mapped_column()
    ip: Mapped[IPv4Address | IPv6Address] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str] = mapped_column(nullable=True)
    device: Mapped[str] = mapped_column(nullable=True)
    platform: Mapped[str] = mapped_column(nullable=True)
    location: Mapped[str] = mapped_column(nullable=True)
    last_used_at: Mapped[datetime] = mapped_column(nullable=True)
    revoked_at: Mapped[datetime] = mapped_column(nullable=True)
    created_at: Mapped[datetime] = mapped_column(server_default=func.now(),nullable=False)

    user: Mapped["User"] = relationship(
        "User",
        back_populates="sessions",
    )