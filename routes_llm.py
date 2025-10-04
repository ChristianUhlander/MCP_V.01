# routes_llm.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import os

router = APIRouter()

class Message(BaseModel):
    role: str
    content: str

class LLMRequest(BaseModel):
    model: str
    messages: List[Message]
    max_tokens: Optional[int] = 1000
    temperature: Optional[float] = 0.7

class LLMResponse(BaseModel):
    response: Dict[str, Any]
    raw: Optional[Dict[str, Any]] = None

@router.post("/api/llm")
async def call_llm(req: LLMRequest):
    """
    Proxy LLM requests to OpenAI API.
    """
    try:
        import requests
    except ImportError:
        raise HTTPException(status_code=500, detail="requests library not installed")
    
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")
    
    openai_payload = {
        "model": req.model,
        "messages": [{"role": m.role, "content": m.content} for m in req.messages],
        "max_tokens": req.max_tokens,
        "temperature": req.temperature
    }
    
    try:
        response = requests.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            },
            json=openai_payload,
            timeout=120
        )
        response.raise_for_status()
        data = response.json()
        
        content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        return {
            "response": {
                "content": content,
                "model": data.get("model"),
                "usage": data.get("usage", {})
            },
            "raw": data
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI API error: {str(e)}")
