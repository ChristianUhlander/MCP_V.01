# repo.py
from typing import Optional
from sqlalchemy import select
from db import db_session
from db_models import Session as DBSession, Thread, Message, ToolRun, RoleEnum

def create_session(title: str, metadata: Optional[dict] = None) -> int:
    with db_session() as s:
        sess = DBSession(title=title, metadata=metadata or {})
        s.add(sess)
        s.flush()
        # Create default main thread
        thread = Thread(session_id=sess.id, name="main")
        s.add(thread)
        s.flush()
        return sess.id

def create_thread(session_id: int, name: str, root_message_id: Optional[int] = None) -> int:
    with db_session() as s:
        t = Thread(session_id=session_id, name=name, root_message_id=root_message_id)
        s.add(t)
        s.flush()
        return t.id

def add_message(thread_id: int, role: RoleEnum, content: str, parent_message_id: Optional[int], payload: Optional[dict]) -> int:
    with db_session() as s:
        m = Message(thread_id=thread_id, role=role, content=content, parent_message_id=parent_message_id, payload=payload or {})
        s.add(m)
        s.flush()
        return m.id

def log_tool_run(message_id: int, tool_name: str, status: str, command: Optional[str], stdout: Optional[str], stderr: Optional[str], exit_code: Optional[int]):
    with db_session() as s:
        run = ToolRun(
            message_id=message_id, tool_name=tool_name, status=status,
            command=command, stdout=stdout, stderr=stderr, exit_code=exit_code
        )
        s.add(run)

def get_thread_messages(thread_id: int):
    with db_session() as s:
        q = select(Message).where(Message.thread_id == thread_id).order_by(Message.created_at.asc())
        return s.scalars(q).all()

def get_session_threads(session_id: int):
    with db_session() as s:
        q = select(Thread).where(Thread.session_id == session_id).order_by(Thread.created_at.asc())
        return s.scalars(q).all()
