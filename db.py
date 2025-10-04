# Filename: db.py
import os
from contextlib import contextmanager
from typing import Iterator, Optional, Dict, Any

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session

from db_models import Base

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
# Example values:
#   SQLite (dev):  sqlite:///./mcp_history.db
#   Postgres:      postgresql+psycopg2://mcp_user:mcp_pass@localhost:5432/mcp_history
DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./mcp_history.db")

IS_SQLITE = DATABASE_URL.startswith("sqlite")

# For SQLite, allow use across threads (Uvicorn reload, background tasks, etc.)
connect_args: Dict[str, Any] = {"check_same_thread": False} if IS_SQLITE else {}

# -----------------------------------------------------------------------------
# Engine
# -----------------------------------------------------------------------------
engine: Engine = create_engine(
    DATABASE_URL,
    echo=False,           # flip to True when debugging SQL
    future=True,
    connect_args=connect_args,
    pool_pre_ping=True,   # helps avoid stale connections (esp. Postgres)
)

# Apply useful SQLite pragmas
if IS_SQLITE:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):  # type: ignore[no-redef]
        # WAL improves concurrency; NORMAL sync is a good compromise for dev
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
        finally:
            cursor.close()

# -----------------------------------------------------------------------------
# Session factory
# -----------------------------------------------------------------------------
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,      # explicit flushes are safer
    autocommit=False,     # always use transactions
    future=True,
    expire_on_commit=False,  # keep objects usable after commit
)

# -----------------------------------------------------------------------------
# Public helpers
# -----------------------------------------------------------------------------
def init_db() -> None:
    """
    Create all tables if they don't exist.
    Safe to call at startup.
    """
    Base.metadata.create_all(bind=engine)


@contextmanager
def db_session() -> Iterator[Session]:
    """
    Usage:
        with db_session() as s:
            s.add(obj)
            ...
    Commits on success, rolls back on exception.
    """
    session: Session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


# Optional: handy getter if you prefer manual session management somewhere
def get_session() -> Session:
    """
    Create a new session (remember to close it).
    Prefer using `with db_session()` where possible.
    """
    return SessionLocal()


# Optional: quick health check utility you can call in a /health route
def db_healthcheck() -> bool:
    """
    Returns True if a trivial round-trip works.
    """
    try:
        with engine.connect() as conn:
            conn.exec_driver_sql("SELECT 1")
        return True
    except Exception:
        return False
