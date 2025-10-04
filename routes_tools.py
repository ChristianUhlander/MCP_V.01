# routes_tools.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
import subprocess
import shlex

router = APIRouter()

# Tool registry - expand this with your actual Kali tools
TOOLS_REGISTRY = {
    "nmap": {
        "available": True,
        "description": "Network scanner for port scanning and service detection",
        "presets": ["quick-scan", "full-scan", "stealth-scan"],
        "command": "nmap"
    },
    "nikto": {
        "available": True,
        "description": "Web server scanner for vulnerabilities",
        "presets": ["basic-scan", "full-scan"],
        "command": "nikto"
    },
    "gobuster": {
        "available": True,
        "description": "Directory/file & DNS busting tool",
        "presets": ["dir-common", "dir-full", "dns-subdomain"],
        "command": "gobuster"
    },
    "sqlmap": {
        "available": True,
        "description": "Automatic SQL injection and database takeover tool",
        "presets": ["basic-test", "full-test"],
        "command": "sqlmap"
    },
    "hydra": {
        "available": True,
        "description": "Network logon cracker supporting numerous protocols",
        "presets": ["ssh-bruteforce", "http-bruteforce"],
        "command": "hydra"
    },
    "dirb": {
        "available": True,
        "description": "Web content scanner",
        "presets": ["common", "big"],
        "command": "dirb"
    }
}

@router.get("/api/tools")
async def list_tools():
    """
    List all available tools and their metadata.
    """
    return {"tools": TOOLS_REGISTRY}

@router.get("/api/tools/{tool_name}/presets")
async def get_tool_presets(tool_name: str):
    """
    Get available presets for a specific tool.
    """
    if tool_name not in TOOLS_REGISTRY:
        raise HTTPException(status_code=404, detail=f"Tool '{tool_name}' not found")
    
    tool_info = TOOLS_REGISTRY[tool_name]
    presets = {}
    
    # Define preset commands (expand this with actual preset logic)
    if tool_name == "nmap":
        presets = {
            "quick-scan": "-T4 -F",
            "full-scan": "-sV -sC -p-",
            "stealth-scan": "-sS -T2"
        }
    elif tool_name == "nikto":
        presets = {
            "basic-scan": "-Tuning 123",
            "full-scan": "-Tuning 123456789"
        }
    elif tool_name == "gobuster":
        presets = {
            "dir-common": "dir -w /usr/share/wordlists/dirb/common.txt",
            "dir-full": "dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
        }
    
    return {"presets": presets, "available": tool_info.get("presets", [])}

class ValidateRequest(BaseModel):
    command: str

class ValidateResponse(BaseModel):
    valid: bool
    reason: Optional[str] = None
    tool: Optional[str] = None

@router.post("/api/validate", response_model=ValidateResponse)
async def validate_command(req: ValidateRequest):
    """
    Validate if a command is safe to execute.
    """
    cmd = req.command.strip()
    
    if not cmd:
        return ValidateResponse(valid=False, reason="Empty command")
    
    # Extract tool name
    parts = shlex.split(cmd)
    tool_name = parts[0] if parts else ""
    
    # Check if tool is in registry
    if tool_name not in TOOLS_REGISTRY:
        return ValidateResponse(
            valid=False,
            reason=f"Tool '{tool_name}' not available",
            tool=tool_name
        )
    
    # Check for dangerous patterns
    dangerous = [";", "&&", "||", "|", ">", "<", "`", "$"]
    for char in dangerous:
        if char in cmd:
            return ValidateResponse(
                valid=False,
                reason=f"Dangerous character '{char}' not allowed",
                tool=tool_name
            )
    
    return ValidateResponse(valid=True, tool=tool_name)

class CommandRequest(BaseModel):
    command: str
    session_id: Optional[int] = None

class CommandResponse(BaseModel):
    success: bool
    stdout: str
    stderr: str
    return_code: int
    execution_time: float
    timed_out: bool
    error: Optional[str] = None

@router.post("/api/command", response_model=CommandResponse)
async def execute_command(req: CommandRequest):
    """
    Execute a validated command.
    """
    import time
    
    # Validate first
    validation = await validate_command(ValidateRequest(command=req.command))
    if not validation.valid:
        raise HTTPException(status_code=400, detail=validation.reason)
    
    # Execute command
    start_time = time.time()
    try:
        result = subprocess.run(
            shlex.split(req.command),
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        execution_time = time.time() - start_time
        
        return CommandResponse(
            success=(result.returncode == 0),
            stdout=result.stdout,
            stderr=result.stderr,
            return_code=result.returncode,
            execution_time=execution_time,
            timed_out=False
        )
        
    except subprocess.TimeoutExpired:
        execution_time = time.time() - start_time
        return CommandResponse(
            success=False,
            stdout="",
            stderr="Command timed out after 300 seconds",
            return_code=-1,
            execution_time=execution_time,
            timed_out=True,
            error="Timeout"
        )
    except Exception as e:
        execution_time = time.time() - start_time
        return CommandResponse(
            success=False,
            stdout="",
            stderr=str(e),
            return_code=-1,
            execution_time=execution_time,
            timed_out=False,
            error=str(e)
        )
