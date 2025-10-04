# File: /mnt/data/openAI_mcp.py
#!/usr/bin/env python3
"""
Enhanced Kali Tools API Server - v2 (OpenAI/LM Studio aware, crash-hardened)
Includes:
- JSON parsing helpers for LLM output.
- Automatic JSON re-prompt/retry loop in /api/llm.
"""

import argparse
import json
import logging
import os
import re
import shlex
import shutil
import subprocess
import sys
import traceback
import threading
import time
from datetime import datetime
from typing import Dict, Any, List, Tuple, Optional, Callable
from dataclasses import dataclass, asdict
from pathlib import Path

import requests
from flask import Flask, request, jsonify, make_response
from db import init_db
init_db()
# --------------------
# OpenAI adaptive import
# --------------------
OPENAI_LEGACY = False        # openai.ChatCompletion style
OPENAI_CLIENT_STYLE = False  # OpenAI() client style
_openai = None               # module or client
_openai_models_ok = False

try:
    from openai import OpenAI  # type: ignore
    def _mk_client(api_key: str):
        return OpenAI(api_key=api_key)
    OPENAI_CLIENT_STYLE = True
except Exception:
    try:
        import openai as _openai  # legacy module
        OPENAI_LEGACY = True
    except Exception:
        _openai = None

# --------------------
# Logging
# --------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)8s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("openAI_mcp")

# --------------------
# Configurable defaults (via env)
# --------------------
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = int(os.environ.get("COMMAND_TIMEOUT", 180))
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o")
OPENAI_TIMEOUT = int(os.environ.get("OPENAI_TIMEOUT", 30))
LMSTUDIO_URL = os.environ.get("LMSTUDIO_URL", "").strip()  # e.g., http://127.0.0.1:11434/v1

app = Flask(__name__)

# --------------------
# Tiny CORS
# --------------------
@app.after_request
def _add_cors_headers(resp):
    resp.headers["Access-Control-Allow-Origin"] = request.headers.get("Origin", "*")
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return resp

# -------------------------------------
# Tool config dataclass & expanded tools
# -------------------------------------
@dataclass
class ToolConfig:
    name: str
    binary: str
    description: str
    default_args: str = ""
    timeout: int = 180
    max_threads: int = 50
    safe_options: List[str] = None
    forbidden_options: List[str] = None
    parameter_builders: Dict[str, Callable] = None

    def __post_init__(self):
        if self.safe_options is None:
            self.safe_options = []
        if self.forbidden_options is None:
            self.forbidden_options = []
        if self.parameter_builders is None:
            self.parameter_builders = {}

TOOL_CONFIGS = {
    # (trimmed tool list kept identical to previous message)
    "nmap": ToolConfig(
        name="nmap",
        binary="nmap",
        description="Network discovery and security auditing",
        default_args="-T4 -Pn --max-retries 1 --host-timeout 90s",
        safe_options=["-sS", "-sT", "-sU", "-sV", "-sC", "-O", "-A", "-F", "--top-ports"],
        parameter_builders={
            "quick_scan": lambda t: f"nmap -T4 -F {t}",
            "service_scan": lambda t: f"nmap -sV -sC {t}",
            "full_scan": lambda t: f"nmap -A -T4 {t}"
        }
    ),
    # ... (other tools unchanged)
}

# --------------------
# Session dataclass & storage
# --------------------
SESSIONS: Dict[str, Any] = {}

@dataclass
class Session:
    id: str
    goal: str
    created_at: datetime
    commands: List[Dict[str, Any]]
    current_target: str = ""

    def add_command(self, command: str, result: Dict[str, Any]):
        self.commands.append({
            "timestamp": datetime.now().isoformat(),
            "command": command,
            "result": result
        })

# --------------------
# Discover tools installed
# --------------------
def discover_available_tools() -> Dict[str, bool]:
    available = {}
    for tool_name, config in TOOL_CONFIGS.items():
        bin_path = shutil.which(config.binary)
        available[tool_name] = bin_path is not None
        if available[tool_name]:
            logger.info(f"✓ Tool '{tool_name}' found at {bin_path}")
        else:
            logger.debug(f"✗ Tool '{tool_name}' not found")
    return available

AVAILABLE_TOOLS = discover_available_tools()

# --------------------
# Safety tokens & validators
# --------------------
FORBIDDEN_TOKENS = {";", "&&", "||", "|", ">", ">>", "<", "`", "$(", ")", "rm", "dd", "mkfs", "shutdown", "reboot"}

def tokenize_safe(cmd: str) -> Tuple[Optional[List[str]], Optional[str]]:
    try:
        tokens = shlex.split(cmd, posix=True)
    except Exception as e:
        return None, f"Failed to parse command: {e}"

    if not tokens:
        return None, "Empty command."

    if any(tok in FORBIDDEN_TOKENS for tok in tokens):
        forbidden = [tok for tok in tokens if tok in FORBIDDEN_TOKENS]
        return None, f"Command contains forbidden tokens: {forbidden}"

    cmd_lower = cmd.lower()
    if any(pattern in cmd_lower for pattern in ["sudo ", "su ", "/etc/", "/root/", "/home/"]):
        return None, "Command contains suspicious patterns (sudo/su or sensitive paths)."

    return tokens, None

def is_command_allowed(tokens: List[str]) -> Tuple[bool, str]:
    if not tokens:
        return False, "Empty command"

    bin_name = tokens[0]
    if bin_name not in TOOL_CONFIGS:
        return False, f"Tool '{bin_name}' is not configured. Available tools: {list(TOOL_CONFIGS.keys())}"

    if not AVAILABLE_TOOLS.get(bin_name, False):
        return False, f"Tool '{bin_name}' is not installed or not found in PATH"

    config = TOOL_CONFIGS[bin_name]
    if config.forbidden_options:
        for token in tokens[1:]:
            if any(forbidden in token for forbidden in config.forbidden_options):
                return False, f"Forbidden option detected: {token}"

    return True, "OK"

# --------------------
# Command execution wrapper
# --------------------
class EnhancedCommandExecutor:
    def __init__(self, command: str, tool_config: ToolConfig):
        self.command = command
        self.config = tool_config
        self.timeout = tool_config.timeout or COMMAND_TIMEOUT
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.start_time = None
        self.end_time = None
        self.return_code = None
        self.timed_out = False

    def _read_stream(self, pipe, sink_attr: str):
        try:
            for line in iter(pipe.readline, ''):
                if not line:
                    break
                setattr(self, sink_attr, getattr(self, sink_attr) + line)
        except Exception as e:
            logger.error(f"Error reading stream: {e}")

    def execute(self) -> Dict[str, Any]:
        logger.info(f"🔧 Executing [{self.config.name}]: {self.command}")
        self.start_time = time.time()

        try:
            self.process = subprocess.Popen(
                self.command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            stdout_thread = threading.Thread(target=self._read_stream, args=(self.process.stdout, "stdout_data"), daemon=True)
            stderr_thread = threading.Thread(target=self._read_stream, args=(self.process.stderr, "stderr_data"), daemon=True)
            stdout_thread.start()
            stderr_thread.start()

            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                stdout_thread.join(timeout=2)
                stderr_thread.join(timeout=2)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"⏱  Command timed out after {self.timeout}s")
                try:
                    self.process.terminate()
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning("🔪 Killing unresponsive process")
                    self.process.kill()
                self.return_code = -1

            self.end_time = time.time()
            execution_time = self.end_time - self.start_time

            success = (self.return_code == 0) or (self.timed_out and (self.stdout_data or self.stderr_data))

            result = {
                "tool": self.config.name,
                "command": self.command,
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "execution_time": round(execution_time, 2),
                "partial_results": self.timed_out and (self.stdout_data or self.stderr_data),
                "timestamp": datetime.now().isoformat()
            }

            if success:
                logger.info(f"✅ Command completed successfully in {execution_time:.2f}s")
            else:
                logger.error(f"❌ Command failed with return code {self.return_code}")

            return result

        except Exception as e:
            self.end_time = time.time()
            logger.error(f"💥 Error executing command: {e}")
            logger.error(traceback.format_exc())

            return {
                "tool": self.config.name,
                "command": self.command,
                "stdout": self.stdout_data,
                "stderr": f"Execution error: {e}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "execution_time": (self.end_time - self.start_time) if self.start_time else 0,
                "partial_results": bool(self.stdout_data),
                "timestamp": datetime.now().isoformat()
            }

def execute_command(command: str) -> Dict[str, Any]:
    tokens, err = tokenize_safe(command)
    if err:
        return {"error": err, "success": False}

    tool_name = tokens[0]
    config = TOOL_CONFIGS.get(tool_name)
    if not config:
        return {"error": f"No configuration for tool '{tool_name}'", "success": False}

    executor = EnhancedCommandExecutor(command, config)
    return executor.execute()

# --------------------
# JSON extraction helpers
# --------------------
def strip_code_fences(raw: str) -> str:
    if not isinstance(raw, str):
        return raw
    s = raw.strip()
    if s.startswith("```"):
        first_nl = s.find("\n")
        if first_nl != -1:
            s = s[first_nl + 1 :]
        if s.endswith("```"):
            s = s[:-3]
    return s.strip()

def _extract_json_strict(raw: str) -> Optional[Dict[str, Any]]:
    if not raw:
        return None
    txt = strip_code_fences(raw)
    try:
        obj = json.loads(txt)
        return obj if isinstance(obj, dict) else None
    except Exception:
        pass

    s = txt
    in_str = False
    esc = False
    depth = 0
    start = -1
    for i, ch in enumerate(s):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        else:
            if ch == '"':
                in_str = True
                continue
            if ch == "{":
                if depth == 0:
                    start = i
                depth += 1
                continue
            if ch == "}":
                if depth > 0:
                    depth -= 1
                    if depth == 0 and start != -1:
                        candidate = s[start : i + 1]
                        try:
                            obj = json.loads(candidate)
                            return obj if isinstance(obj, dict) else None
                        except Exception:
                            start = -1
                continue
    return None

def _validate_schema(obj: Dict[str, Any], required_keys: Optional[List[str]] = None) -> Tuple[bool, str]:
    if obj is None:
        return False, "No object"
    keys = required_keys or []
    for k in keys:
        if k not in obj:
            return False, f"Missing key: {k}"
        v = obj[k]
        if v is None or (isinstance(v, str) and v.strip() == ""):
            return False, f"Empty value for key: {k}"
    return True, "OK"

def parse_llm_json(raw: str, required_keys: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    obj = _extract_json_strict(raw)
    if not obj:
        try:
            cand: Dict[str, Any] = {}
            for k in (required_keys or []):
                m = re.search(rf'"{re.escape(k)}"\s*:\s*"([^"]+)"', raw)
                if m:
                    cand[k] = m.group(1)
            ok, _ = _validate_schema(cand, required_keys)
            if ok:
                obj = cand
        except Exception:
            obj = None
    return obj

def build_reprompt_message(required_keys: List[str], hint: Optional[str] = None) -> str:
    """
    Strong constraint message to coerce pure JSON. Keep terse to reduce drift.
    """
    keys = ", ".join(required_keys) if required_keys else "(no specific keys)"
    base = (
        "Return ONLY a strict JSON object. "
        "No code fences, no backticks, no comments, no prose, no trailing text. "
        f"Required keys: {keys}."
    )
    if hint:
        base += f" {hint.strip()}"
    return base

# --------------------
# API endpoints (validate/command/tools/sessions/health/root)
# --------------------
@app.route("/api/validate", methods=["POST", "OPTIONS"])
def validate():
    if request.method == "OPTIONS":
        return make_response(("", 204))
    try:
        data = request.get_json(force=True) or {}
        cmd = (data.get("command") or "").strip()

        if not cmd:
            return jsonify({"valid": False, "reason": "Missing command"}), 400

        tokens, err = tokenize_safe(cmd)
        if err:
            return jsonify({"valid": False, "reason": err, "tokens": []}), 200

        allowed, reason = is_command_allowed(tokens)

        response = {"valid": allowed, "reason": reason, "tokens": tokens}
        if allowed and tokens:
            tool_name = tokens[0]
            config = TOOL_CONFIGS.get(tool_name)
            if config:
                response["tool_info"] = {
                    "name": config.name,
                    "description": config.description,
                    "timeout": config.timeout
                }

        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Validation error: {e}")
        return jsonify({"valid": False, "reason": f"Server error: {e}"}), 500

@app.route("/api/command", methods=["POST", "OPTIONS"])
def generic_command():
    if request.method == "OPTIONS":
        return make_response(("", 204))
    try:
        params = request.get_json(force=True) or {}
        command = (params.get("command") or "").strip()
        session_id = params.get("session_id")

        if not command:
            return jsonify({"error": "Command parameter is required"}), 400

        tokens, err = tokenize_safe(command)
        if err:
            return jsonify({"error": err}), 400

        allowed, reason = is_command_allowed(tokens)
        if not allowed:
            return jsonify({"error": reason}), 400

        result = execute_command(command)

        if session_id and session_id in SESSIONS:
            SESSIONS[session_id].add_command(command, result)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Command execution error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500

@app.route("/api/tools", methods=["GET"])
def list_tools():
    tools_info = {}
    for tool_name, config in TOOL_CONFIGS.items():
        tools_info[tool_name] = {
            "name": config.name,
            "binary": config.binary,
            "description": config.description,
            "available": AVAILABLE_TOOLS.get(tool_name, False),
            "timeout": config.timeout,
            "presets": list(config.parameter_builders.keys()) if config.parameter_builders else []
        }

    return jsonify({
        "tools": tools_info,
        "summary": {
            "total_configured": len(TOOL_CONFIGS),
            "available": sum(1 for v in AVAILABLE_TOOLS.values() if v),
            "missing": [k for k, v in AVAILABLE_TOOLS.items() if not v]
        }
    })

@app.route("/api/tools/<tool_name>/presets", methods=["GET"])
def get_tool_presets(tool_name):
    if tool_name not in TOOL_CONFIGS:
        return jsonify({"error": f"Tool '{tool_name}' not configured"}), 404

    config = TOOL_CONFIGS[tool_name]
    presets = {}

    if config.parameter_builders:
        for preset_name, builder in config.parameter_builders.items():
            try:
                import inspect
                sig = inspect.signature(builder)
                params = list(sig.parameters.keys())
                presets[preset_name] = {"parameters": params, "description": f"Preset for {preset_name.replace('_', ' ')}"}
            except Exception:
                presets[preset_name] = {"parameters": ["target"], "description": "Standard preset"}

    return jsonify({"tool": tool_name, "presets": presets})

@app.route("/api/tools/<tool_name>/preset/<preset_name>", methods=["POST"])
def execute_preset(tool_name, preset_name):
    try:
        if tool_name not in TOOL_CONFIGS:
            return jsonify({"error": f"Tool '{tool_name}' not configured"}), 404

        if not AVAILABLE_TOOLS.get(tool_name, False):
            return jsonify({"error": f"Tool '{tool_name}' is not available"}), 400

        config = TOOL_CONFIGS[tool_name]
        if not config.parameter_builders or preset_name not in config.parameter_builders:
            return jsonify({"error": f"Preset '{preset_name}' not found"}), 404

        params = request.get_json(force=True) or {}
        builder = config.parameter_builders[preset_name]

        try:
            if len(params) == 0:
                return jsonify({"error": "Parameters required for preset"}), 400
            elif len(params) == 1:
                command = builder(list(params.values())[0])
            else:
                command = builder(**params)
        except TypeError as e:
            return jsonify({"error": f"Invalid parameters for preset: {e}"}), 400

        tokens, err = tokenize_safe(command)
        if err:
            return jsonify({"error": err}), 400

        allowed, reason = is_command_allowed(tokens)
        if not allowed:
            return jsonify({"error": reason}), 400

        result = execute_command(command)
        return jsonify(result)

    except Exception as e:
        logger.error(f"Preset execution error: {e}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error: {e}"}), 500

@app.route("/api/sessions", methods=["POST"])
def create_session():
    try:
        data = request.get_json(force=True) or {}
        goal = data.get("goal", "").strip()

        if not goal:
            return jsonify({"error": "Goal is required"}), 400

        session_id = f"session_{int(time.time())}_{len(SESSIONS)}"
        session = Session(
            id=session_id,
            goal=goal,
            created_at=datetime.now(),
            commands=[],
            current_target=data.get("target", "")
        )
        SESSIONS[session_id] = session

        logger.info(f"📝 Created session {session_id} with goal: {goal}")

        return jsonify({
            "session_id": session_id,
            "goal": goal,
            "created_at": session.created_at.isoformat(),
            "target": session.current_target
        })

    except Exception as e:
        logger.error(f"Session creation error: {e}")
        return jsonify({"error": f"Server error: {e}"}), 500

@app.route("/api/sessions/<session_id>", methods=["GET"])
def get_session(session_id):
    if session_id not in SESSIONS:
        return jsonify({"error": "Session not found"}), 404
    return jsonify(asdict(SESSIONS[session_id]))

@app.route("/api/sessions", methods=["GET"])
def list_sessions():
    sessions_info = []
    for session_id, session in SESSIONS.items():
        sessions_info.append({
            "id": session.id,
            "goal": session.goal,
            "created_at": session.created_at.isoformat(),
            "commands_count": len(session.commands),
            "current_target": session.current_target
        })
    return jsonify({"sessions": sessions_info, "total": len(SESSIONS)})

@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({
        "status": "healthy",
        "message": "Enhanced Kali Linux Tools API Server (OpenAI/LM Studio aware)",
        "version": "2.2-openai-lms",
        "tools_summary": {
            "configured": len(TOOL_CONFIGS),
            "available": sum(1 for v in AVAILABLE_TOOLS.values() if v),
            "missing": [k for k, v in AVAILABLE_TOOLS.items() if not v]
        },
        "sessions": {
            "active": len(SESSIONS),
            "total_commands": sum(len(s.commands) for s in SESSIONS.values())
        },
        "uptime_epoch": int(time.time()),
        "debug_mode": DEBUG_MODE,
        "openai": {
            "sdk_style": "client" if OPENAI_CLIENT_STYLE else ("legacy" if OPENAI_LEGACY else "none"),
            "configured_api_key": bool(OPENAI_API_KEY),
            "models_ok": _openai_models_ok
        },
        "lmstudio": {
            "configured_url": bool(LMSTUDIO_URL)
        }
    })

@app.route("/", methods=["GET"])
def root():
    return jsonify({
        "name": "Enhanced Kali Tools API (OpenAI/LM Studio aware)",
        "version": "2.2-openai-lms",
        "description": "Enhanced prototyping environment for security tools with optional OpenAI or LM Studio connectivity.",
        "endpoints": {
            "health": "GET /health",
            "tools": "GET /api/tools",
            "validate": "POST /api/validate",
            "command": "POST /api/command",
            "presets": "GET /api/tools/{tool}/presets",
            "preset_exec": "POST /api/tools/{tool}/preset/{preset}",
            "sessions": "POST /api/sessions",
            "llm": "POST /api/llm (proxy to OpenAI or LM Studio if configured)"
        }
    })

# --------------------
# OpenAI/LMStudio integration
# --------------------
def openai_configured() -> bool:
    if OPENAI_CLIENT_STYLE and isinstance(_openai, object):
        return bool(_openai) and bool(OPENAI_API_KEY)
    if OPENAI_LEGACY and _openai is not None:
        return bool(OPENAI_API_KEY)
    return False

def initialize_openai(api_key: Optional[str] = None) -> bool:
    global _openai, _openai_models_ok
    key = api_key or OPENAI_API_KEY
    if not key:
        logger.warning("No OPENAI_API_KEY provided. OpenAI disabled.")
        return False

    try:
        if OPENAI_CLIENT_STYLE:
            _openai = _mk_client(key)
            try:
                models = _openai.models.list()
                _openai_models_ok = True if getattr(models, "data", None) is not None else False
                logger.info(f"OpenAI (client) models accessible: {_openai_models_ok}")
            except Exception as e:
                logger.info(f"Model list failed ({e}); trying micro chat ping.")
                _ = _openai.chat.completions.create(
                    model=OPENAI_MODEL,
                    messages=[{"role": "system", "content": "ping"}, {"role": "user", "content": "hello"}],
                    max_tokens=1,
                    timeout=OPENAI_TIMEOUT
                )
                _openai_models_ok = True
            return True

        elif OPENAI_LEGACY and _openai is not None:
            _openai.api_key = key  # type: ignore
            try:
                _ = _openai.Model.list()  # type: ignore
                _openai_models_ok = True
            except Exception as e:
                logger.info(f"Legacy Model.list failed ({e}); trying micro chat ping.")
                _openai.ChatCompletion.create(  # type: ignore
                    model=OPENAI_MODEL,
                    messages=[{"role": "system", "content": "ping"}, {"role": "user", "content": "hello"}],
                    max_tokens=1,
                    timeout=OPENAI_TIMEOUT
                )
                _openai_models_ok = True
            return True

        else:
            logger.warning("OpenAI SDK not installed.")
            return False

    except Exception as e:
        logger.warning(f"OpenAI initialization failed: {e}")
        return False

def _openai_chat(messages: List[Dict[str, str]], model: str, max_tokens: int, timeout: int) -> Dict[str, Any]:
    if OPENAI_CLIENT_STYLE and _openai:
        resp = _openai.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            timeout=timeout
        )
        choice = resp.choices[0] if resp.choices else None
        content = choice.message.content if choice and getattr(choice, "message", None) else None
        role = choice.message.role if choice and getattr(choice, "message", None) else "assistant"
        return {
            "model": model,
            "id": getattr(resp, "id", None),
            "created": getattr(resp, "created", None),
            "usage": getattr(resp, "usage", None) and resp.usage.dict(),
            "message": {"role": role, "content": content}
        }

    elif OPENAI_LEGACY and _openai is not None:
        resp = _openai.ChatCompletion.create(  # type: ignore
            model=model,
            messages=messages,
            max_tokens=max_tokens,
            timeout=timeout
        )
        msg = resp["choices"][0]["message"] if resp.get("choices") else None
        return {
            "model": model,
            "id": resp.get("id"),
            "created": resp.get("created"),
            "usage": resp.get("usage"),
            "message": msg
        }

    raise RuntimeError("OpenAI not configured")

def _lmstudio_chat(messages: List[Dict[str, str]], model: str, max_tokens: int, timeout: int) -> Dict[str, Any]:
    if not LMSTUDIO_URL:
        raise RuntimeError("LM Studio not configured")
    url = LMSTUDIO_URL.rstrip("/") + "/chat/completions" if "/v1" in LMSTUDIO_URL else LMSTUDIO_URL.rstrip("/") + "/v1/chat/completions"
    payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
    r = requests.post(url, json=payload, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    choice = (data.get("choices") or [None])[0]
    msg = choice and choice.get("message")
    return {
        "model": data.get("model", model),
        "id": data.get("id"),
        "created": data.get("created"),
        "usage": data.get("usage"),
        "message": msg
    }

# --------------------
# /api/llm with JSON retry
# --------------------
@app.route("/api/llm", methods=["POST", "OPTIONS"])
def llm_proxy():
    if request.method == "OPTIONS":
        return make_response(("", 204))
    payload = request.get_json(force=True) or {}
    messages = payload.get("messages")
    model = payload.get("model", OPENAI_MODEL)
    max_tokens = int(payload.get("max_tokens", 512))

    expect_json = bool(payload.get("expect_json", False))
    required_keys = payload.get("required_keys") or []
    if not isinstance(required_keys, list):
        required_keys = []
    force_json = bool(payload.get("force_json", False))
    retry_json = int(payload.get("retry_json", 0))
    reprompt_hint = (payload.get("reprompt_hint") or "").strip()

    if not messages:
        return jsonify({"error": "messages (chat history) is required"}), 400

    def _call_provider(msgs: List[Dict[str, str]]) -> Dict[str, Any]:
        if openai_configured():
            logger.info(f"➡ Forwarding LLM request to OpenAI (model={model})")
            return _openai_chat(msgs, model, max_tokens, OPENAI_TIMEOUT)
        elif LMSTUDIO_URL:
            logger.info(f"➡ Forwarding LLM request to LM Studio (model={model})")
            return _lmstudio_chat(msgs, model, max_tokens, OPENAI_TIMEOUT)
        else:
            raise RuntimeError("No LLM configured. Set OPENAI_API_KEY or LMSTUDIO_URL.")

    try:
        attempts = 0
        retries_used = 0
        last_error = None
        data = None
        parsed_json = None
        json_ok = False

        base_messages = list(messages)

        while True:
            attempts += 1
            data = _call_provider(base_messages)
            content = (data.get("message") or {}).get("content") or ""
            if expect_json:
                parsed_json = parse_llm_json(content, required_keys)
                json_ok = parsed_json is not None
                if json_ok:
                    break
                last_error = "Could not obtain valid JSON from LLM."
                if retries_used < retry_json:
                    retries_used += 1
                    # Tighten instructions with a system message; keep original conversation intact.
                    base_messages = list(messages) + [{
                        "role": "system",
                        "content": build_reprompt_message(required_keys, reprompt_hint or "Respond again now.")
                    }]
                    continue
            break

        resp = {"ok": True, **(data or {})}
        if expect_json:
            resp.update({
                "json_ok": json_ok,
                "parsed_json": parsed_json,
                "json_error": None if json_ok else (last_error + " Asking for an alternative…"),
                "retries_used": retries_used,
                "attempts": attempts
            })
            if force_json and not json_ok:
                resp["ok"] = False  # HTTP 200; caller inspects body

        return jsonify(resp)

    except requests.HTTPError as e:
        logger.error(f"LM Studio HTTP error: {e.response.text if hasattr(e, 'response') else e}")
        return jsonify({"error": f"LM Studio call failed: {e}"}), 502
    except Exception as e:
        logger.error(f"LLM proxy error: {e}")
        return jsonify({"error": f"LLM call failed: {e}"}), 500

# --------------------
# CLI args & startup
# --------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Enhanced Kali Linux API Server v2 (OpenAI/LM Studio capable)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--port", type=int, default=API_PORT, help=f"Port (default: {API_PORT})")
    parser.add_argument("--list-tools", action="store_true", help="List configured tools and exit")
    parser.add_argument("--openai", action="store_true", help="Attempt to initialize OpenAI on startup (default if OPENAI_API_KEY set)")
    parser.add_argument("--openai-key", type=str, help="Provide OpenAI API key on CLI (overrides OPENAI_API_KEY env var)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()

    if args.debug:
        DEBUG_MODE = True
        logger.setLevel(logging.DEBUG)

    if args.port and args.port != API_PORT:
        API_PORT = args.port

    logger.info("🚀 Starting Enhanced Kali Tools API Server v2 (OpenAI/LM Studio aware)")
    logger.info(f"📡 Port: {API_PORT} | Debug: {DEBUG_MODE}")

    if args.list_tools:
        print(json.dumps({
            "tools_configured": list(TOOL_CONFIGS.keys()),
            "available": {k: AVAILABLE_TOOLS.get(k, False) for k in TOOL_CONFIGS.keys()}
        }, indent=2))
        sys.exit(0)

    if args.openai or OPENAI_API_KEY:
        ok = initialize_openai(args.openai_key or None)
        if ok:
            logger.info("✅ OpenAI successfully initialized and reachable.")
        else:
            logger.warning("⚠ OpenAI initialization was not successful. /api/llm will use LM Studio (if configured) or be unavailable.")
    else:
        logger.info("OpenAI initialization skipped (no --openai and no OPENAI_API_KEY).")

    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)


# File: /mnt/data/tests/test_json_extraction.py
import os
import sys
import json
import types

# Ensure we can import the module under test.
HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(HERE, ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import openAI_mcp as m  # noqa: E402


def test_strip_code_fences_basic():
    raw = "```json\n{\"a\":1}\n```"
    assert m.strip_code_fences(raw) == '{"a":1}'


def test_extract_json_strict_plain():
    s = '{"name":"Alice","email":"a@x.com"}'
    out = m._extract_json_strict(s)
    assert out == {"name": "Alice", "email": "a@x.com"}


def test_extract_json_strict_fenced():
    s = "```json\n{\"x\": 123}\n```"
    out = m._extract_json_strict(s)
    assert out == {"x": 123}


def test_extract_json_strict_balanced_scan_with_noise():
    s = "blah blah start >> {\"k\":\"v\",\"n\":2} << end"
    out = m._extract_json_strict(s)
    assert out == {"k": "v", "n": 2}


def test_validate_schema_happy_and_edge():
    ok, reason = m._validate_schema({"a": "x", "b": 1}, ["a", "b"])
    assert ok and reason == "OK"
    ok, reason = m._validate_schema({"a": "x"}, ["a", "b"])
    assert not ok and "Missing key" in reason
    ok, reason = m._validate_schema({"a": ""}, ["a"])
    assert not ok and "Empty value" in reason


def test_parse_llm_json_salvage_success():
    # No JSON object, but has key-value text we can salvage
    raw = 'name: "Zed", email: "z@example.com"'
    out = m.parse_llm_json(raw, ["name", "email"])
    assert out == {"name": "Zed", "email": "z@example.com"}


def test_parse_llm_json_salvage_failure():
    raw = "totally unstructured without keys"
    out = m.parse_llm_json(raw, ["name", "email"])
    assert out is None

