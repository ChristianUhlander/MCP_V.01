# Filename: db_models.py
from __future__ import annotations
import enum
from datetime import datetime
from typing import Optional, List
from sqlalchemy import String, Integer, Enum, ForeignKey, DateTime, Text, JSON, Index, LargeBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class RoleEnum(str, enum.Enum):
    user = "user"
    assistant = "assistant"
    tool = "tool"
    system = "system"

class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # renamed from `metadata`
    meta: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    threads: Mapped[List["Thread"]] = relationship(
        back_populates="session", cascade="all, delete-orphan"
    )

class Thread(Base):
    __tablename__ = "threads"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    session_id: Mapped[int] = mapped_column(
        ForeignKey("sessions.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(256), default="main")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    root_message_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("messages.id"), nullable=True
    )

    session: Mapped["Session"] = relationship(back_populates="threads")
    # Disambiguate the FK path to messages
    messages: Mapped[List["Message"]] = relationship(
        "Message",
        back_populates="thread",
        cascade="all, delete-orphan",
        foreign_keys="Message.thread_id",
        passive_deletes=True,
    )

class Message(Base):
    __tablename__ = "messages"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    # FK to Thread
    thread_id: Mapped[int] = mapped_column(
        ForeignKey("threads.id", ondelete="CASCADE"), index=True
    )
    # Self-referential FK to Message
    parent_message_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("messages.id", ondelete="SET NULL"), index=True
    )
    role: Mapped[RoleEnum] = mapped_column(Enum(RoleEnum), index=True)
    content: Mapped[str] = mapped_column(Text)
    tokens: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    payload: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    # Disambiguate and link back to Thread
    thread: Mapped["Thread"] = relationship(
        "Thread",
        back_populates="messages",
        foreign_keys=[thread_id],
        passive_deletes=True,
    )
    # Self-referential parent/children mapping
    parent: Mapped[Optional["Message"]] = relationship(
        "Message",
        remote_side=[id],
        foreign_keys=[parent_message_id],
        backref="children",
        passive_deletes=True,
    )
    tool_runs: Mapped[List["ToolRun"]] = relationship(
        back_populates="message", cascade="all, delete-orphan", passive_deletes=True
    )
    attachments: Mapped[List["Attachment"]] = relationship(
        back_populates="message", cascade="all, delete-orphan", passive_deletes=True
    )

Index("ix_messages_thread_created", Message.thread_id, Message.created_at)

class ToolRun(Base):
    __tablename__ = "tool_runs"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(
        ForeignKey("messages.id", ondelete="CASCADE"), index=True
    )
    tool_name: Mapped[str] = mapped_column(String(128), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)  # queued/running/success/error
    command: Mapped[Optional[str]] = mapped_column(Text)
    stdout: Mapped[Optional[str]] = mapped_column(Text)
    stderr: Mapped[Optional[str]] = mapped_column(Text)
    exit_code: Mapped[Optional[int]] = mapped_column(Integer)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime)

    message: Mapped["Message"] = relationship(back_populates="tool_runs")

class Attachment(Base):
    __tablename__ = "attachments"
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(
        ForeignKey("messages.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(64))  # "file", "url", "blob"
    name: Mapped[str] = mapped_column(String(256))
    uri: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    bytes: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    # renamed from `metadata`
    meta: Mapped[Optional[dict]] = mapped_column(JSON, default=dict)

    message: Mapped["Message"] = relationship(back_populates="attachments")
