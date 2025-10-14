from __future__ import annotations
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String, Integer, Text
from .db import Base

class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(128))
    action: Mapped[str] = mapped_column(String(64))
    case_id: Mapped[str] = mapped_column(String(64))
    details_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str | None] = mapped_column(String(128))
    hash: Mapped[str] = mapped_column(String(128))
    ip: Mapped[str | None] = mapped_column(String(64))
    ua: Mapped[str | None] = mapped_column(String(256))

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(256), unique=True)
    role: Mapped[str] = mapped_column(String(32))
    api_key: Mapped[str] = mapped_column(String(128), unique=True)

class AccessLog(Base):
    __tablename__ = "access_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[str] = mapped_column(String(32))
    actor: Mapped[str] = mapped_column(String(128))
    endpoint: Mapped[str] = mapped_column(String(128))
    params_json: Mapped[str | None] = mapped_column(Text)
