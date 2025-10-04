# routes_history.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import List, Optional, Any, Dict
from repo import create_session, create_thread, get_thread_messages, get_session_threads, add_message
from db_models import RoleEnum

router = APIRouter()

class CreateSessionReq(BaseModel):
    title: str
    metadata: Optional[Dict[str, Any]] = None

class CreateSessionResp(BaseModel):
    session_id: int
    thread_id: int  # main

@router.post("/api/sessions", response_model=CreateSessionResp)
def api_create_session(req: CreateSessionReq):
    sid = create_session(req.title, req.metadata or {})
    # by contract, repo’s create_session made "main" thread with id=1 of that session
    # we need to fetch threads to get id:
    threads = get_session_threads(sid)
    main_thread_id = threads[0].id
    return CreateSessionResp(session_id=sid, thread_id=main_thread_id)

class CreateBranchReq(BaseModel):
    session_id: int
    from_message_id: int
    name: str = "branch"

class CreateBranchResp(BaseModel):
    thread_id: int

@router.post("/api/branch", response_model=CreateBranchResp)
def api_create_branch(req: CreateBranchReq):
    # start a new thread rooted at an existing message
    tid = create_thread(session_id=req.session_id, name=req.name, root_message_id=req.from_message_id)
    # optional: seed first message by copying content or adding a system note
    add_message(thread_id=tid, role=RoleEnum.system, content=f"Branch from message {req.from_message_id}", parent_message_id=None, payload={})
    return CreateBranchResp(thread_id=tid)

class ThreadHistoryResp(BaseModel):
    thread_id: int
    items: List[Dict[str, Any]]

@router.get("/api/history/{thread_id}", response_model=ThreadHistoryResp)
def api_get_history(thread_id: int):
    msgs = get_thread_messages(thread_id)
    items = []
    for m in msgs:
        items.append({
            "id": m.id,
            "parent_id": m.parent_message_id,
            "role": m.role.value,
            "content": m.content,
            "created_at": m.created_at.isoformat(),
            "payload": m.payload,
            "tool_runs": [
                {
                    "tool_name": tr.tool_name,
                    "status": tr.status,
                    "exit_code": tr.exit_code,
                    "started_at": tr.started_at.isoformat(),
                } for tr in m.tool_runs
            ]
        })
    return ThreadHistoryResp(thread_id=thread_id, items=items)
