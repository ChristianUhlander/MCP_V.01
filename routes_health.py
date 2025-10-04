# Filename: routes_health.py
from fastapi import APIRouter
from db import db_healthcheck

router = APIRouter(tags=["health"])

@router.get("/health")
async def health_check():
    """
    Health check endpoint.
    Returns the status of the API and database connection.
    """
    db_ok = db_healthcheck()
    
    return {
        "status": "healthy" if db_ok else "unhealthy",
        "database": "connected" if db_ok else "disconnected",
        "message": "Enhanced Kali Tools API Server",
        "service": "kali-tools-api"
    }

@router.get("/")
async def root():
    """
    Root endpoint with API information.
    """
    return {
        "message": "Enhanced Kali Tools API Server (with history)",
        "version": "1.0",
        "status": "running",
        "endpoints": {
            "health": "/health",
            "docs": "/docs",
            "openapi": "/openapi.json",
            "api": {
                "llm": "/api/llm",
                "tools": "/api/tools",
                "command": "/api/command",
                "validate": "/api/validate",
                "sessions": "/api/sessions",
                "history": "/api/history"
            }
        }
    }
