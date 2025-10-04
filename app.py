# app.py
from fastapi import FastAPI

def create_app() -> FastAPI:
    api = FastAPI(title="Enhanced Kali Tools API Server (with history)")

    # Lazy imports avoid circulars while we debug
    from db import init_db
    init_db()

    from routes_llm import router as llm_router
    from routes_tools import router as tools_router
    from routes_history import router as history_router
    from routes_health import router as health_router 
    api.include_router(llm_router)
    api.include_router(tools_router)
    api.include_router(history_router)
    api.include_router(health_router) 
    return api

app = create_app()
