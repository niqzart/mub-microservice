from __future__ import annotations

from sqlalchemy import Column
from sqlalchemy.sql.sqltypes import Integer, String

from common import Base


class BlockedModToken(Base):  # TODO replace with full session control
    __tablename__ = "blocked-mod-tokens"

    id = Column(Integer, primary_key=True)
    jti = Column(String(36), nullable=False)
