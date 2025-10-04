#!/usr/bin/env python3
# ~/MCR/chatClient.py
"""
Chat Client — Permissive JSON handling + resilient planner/executor + configurable timeouts.

Updates:
- Global --timeout (seconds, default 2000). Applied to all HTTP calls (LLM + API).
- Health check remains 10s to avoid startup hangs.

JSON handling remains ultra-permissive: accepts arrays, YAML-ish, single quotes, trailing commas,
escaped JSON-strings, wrong keys/casing, extra prose; maps synonyms and backfills missing fields.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

import requests

# ---------------- Schema & prompts ----------------
SCHEMA_KEYS = ["rationale", "command", "expected_outcome", "next_steps"]

JSON_SCHEMA = {
    "name": "cyber_step",
    "schema": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "rationale": {"type": "string"},
            "command": {"type": "string"},
            "expected_outcome": {"type": "string"},
            "next_steps": {"type": "string"},
        },
        "required": SCHEMA_KEYS,
    },
}

INITIAL_SYSTEM = """You are a cybersecurity expert assistant with access to tools via an HTTP API.

Available tools and their capabilities:
{tools_info}

Return ONLY valid minified JSON with exactly these keys:
{{"rationale":"why this command/approach","command":"exact command to run","expected_outcome":"what we expect to find","next_steps":"what to do after this"}}

Rules:
- ONE command at a time
- Prefer safe recon first
- Respect legal scope
- Use presets when sensible
- RAW JSON ONLY. No code fences. No markdown. No explanations. No trailing text."""

FOLLOWUP_SYSTEM = """Return ONLY minified JSON with the SAME 4 keys.
No code fences. No markdown. No explanations. No trailing text.

Previous command: {last_command}
Result summary: {result_summary}

Pick the single best next step based on outcome. If rejected/failed, propose a safer alternative."""

# ---------------- Permissive JSON utilities ----------------
_SYNONYMS = {
    "rationale": {
        "rationale", "why", "reason", "justification", "analysis", "strategy",
        "context", "motivation", "thoughts", "because"
    },
    "command": {
        "command", "cmd", "action", "shell", "bash", "run", "execute", "exec",
        "instruction", "tool_command", "cli", "step", "cmdline", "cmd_line"
    },
    "expected_outcome": {
        "expected_outcome", "expected", "result", "anticipated_result",
        "what_we_expect", "output", "goal", "observation", "expectation",
        "expectedresult", "expected_result"
    },
    "next_steps": {
        "next_steps", "next", "follow_up", "followup", "then", "after",
        "subsequent", "plan", "continue", "what_next", "nextstep", "next_step"
    },
}
_TOOL_WORDS = r"(nmap|nikto|gobuster|sqlmap|hydra|dirb|curl|wget|ssh|nc|netcat)"
_CMD_LINE_RE = re.compile(rf"(?mi)^\s*(?:[\$>#]\s*)?(?:{_TOOL_WORDS})\b[^\n]*")
_BARE_KEY_RE = re.compile(r'(?m)^\s*([A-Za-z_][\w\- ]*)\s*:\s*(.+)$')

def _lower_snake(s: str) -> str:
    s = re.sub(r"[\s\-]+", "_", s.strip())
    return s.lower()

def _map_key(k: str) -> Optional[str]:
    k_norm = _lower_snake(k)
    for canon, syns in _SYNONYMS.items():
        if k_norm == canon or k_norm in syns:
            return canon
    if k_norm in {"nextstep"}: return "next_steps"
    if k_norm in {"why_this", "rational"}: return "rationale"
    if k_norm in {"cmdline", "cmd_line"}: return "command"
    if k_norm in {"expectedresult", "expected_result"}: return "expected_outcome"
    return None

def _strip_code_fences(text: str) -> str:
    t = text.strip()
    t = re.sub(r"^```(?:json|yaml|yml)?\s*", "", t, flags=re.IGNORECASE)
    t = re.sub(r"```$", "", t)
    t = t.replace("```", "")
    return t.strip()

def _json_unescape_if_needed(s: str) -> str:
    try:
        obj = json.loads(s)
        if isinstance(obj, str) and obj.strip().startswith("{"):
            return obj
    except Exception:
        pass
    return s

def _fix_jsonish(s: str) -> str:
    s2 = s
    s2 = re.sub(r'(?<![A-Za-z0-9_])True(?![A-Za-z0-9_])', 'true', s2)
    s2 = re.sub(r'(?<![A-Za-z0-9_])False(?![A-Za-z0-9_])', 'false', s2)
    s2 = re.sub(r'(?<![A-Za-z0-9_])None(?![A-Za-z0-9_])', 'null', s2)
    s2 = re.sub(r"(?<!\\)'", '"', s2)                  # single → double
    s2 = re.sub(r",\s*([}\]])", r"\1", s2)             # trailing commas
    def _quote_keys(m: re.Match) -> str:
        k, v = m.group(1).strip(), m.group(2).strip()
        if k.startswith('"') and k.endswith('"'):
            return m.group(0)
        return f'"{k}": {v}'
    s2 = _BARE_KEY_RE.sub(_quote_keys, s2)
    return s2

def _balanced_json_candidates(s: str) -> List[str]:
    cand, stack = [], []
    for i, ch in enumerate(s):
        if ch in "{[":
            stack.append((ch, i))
        elif ch in "}]":
            if not stack:
                continue
            left, start = stack.pop()
            if (left, ch) in {("{", "}"), ("[", "]")}:
                cand.append(s[start:i+1])
    cand.sort(key=len, reverse=True)
    return cand[:10]

def _score_dict(d: Dict[str, Any]) -> int:
    score, keys = 0, set(_lower_snake(k) for k in d.keys())
    for canon, syns in _SYNONYMS.items():
        if canon in keys:
            v = d.get(canon); score += 3 if isinstance(v, str) and v.strip() else 2
        else:
            for s in syns:
                if s in keys:
                    v = d.get(s); score += 2 if isinstance(v, str) and v.strip() else 1
                    break
    for v in d.values():
        if isinstance(v, str) and _CMD_LINE_RE.search(v):
            score += 3; break
    return score

def _normalize_fields(d: Dict[str, Any]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in list(d.items()):
        canon = _map_key(k)
        if canon:
            out[canon] = v if isinstance(v, str) else json.dumps(v, ensure_ascii=False)
    return out

def _extract_context(system_text: str) -> Tuple[str, str]:
    last_cmd, result_sum = "", ""
    m1 = re.search(r"Previous command:\s*(.+)", system_text)
    if m1: last_cmd = m1.group(1).strip()
    m2 = re.search(r"Result summary:\s*(.+)", system_text, re.DOTALL)
    if m2: result_sum = m2.group(1).strip()
    return last_cmd, result_sum

def _escalate_from_summary(summary: str, target: str, last_cmd: str) -> str:
    s, tgt = summary.lower(), (target or "<target>")
    if "ignored states" in s or "filtered" in s or "no open ports" in s:
        return f"nmap -Pn -sS -p- -T3 {tgt}"
    if "timed out" in s or "timeout" in s:
        return f"nmap -Pn -sS -p- -T2 {tgt}"
    if re.search(r"\b(retry|again|re-?run|rerun)\b", s):
        return last_cmd or f"nmap --preset quick-scan {tgt}"
    return f"nmap -Pn -p- -T3 {tgt}"

def _finalize_plan(partial: Dict[str, str], *, last_command: str, result_summary: str, target: str) -> Dict[str, str]:
    plan = {k: (v if isinstance(v, str) else str(v)) for k, v in partial.items()}
    plan.setdefault("rationale", "Proceed with the next best reconnaissance step based on current findings.")
    plan.setdefault("expected_outcome", "Actionable output to guide the following step.")
    plan.setdefault("next_steps", "Follow up with targeted enumeration based on results.")
    cmd = (plan.get("command") or "").strip()
    if not cmd:
        for v in partial.values():
            if isinstance(v, str):
                m = _CMD_LINE_RE.search(v)
                if m: cmd = m.group(0).strip(); break
        if not cmd and re.search(r"\b(retry|again|re-?run|rerun)\b", plan.get("next_steps","").lower()):
            cmd = last_command
        if not cmd:
            cmd = _escalate_from_summary(result_summary, target, last_command)
    plan["command"] = cmd
    for k in SCHEMA_KEYS:
        plan[k] = (plan.get(k, "") or "").strip()
    return plan

def _parse_yamlish(text: str) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*[-*]\s*(.+)$", line)
        if m: line = m.group(1)
        m2 = re.match(r"^\s*([A-Za-z_][\w \-]*)\s*:\s*(.+)$", line)
        if m2:
            k, v = m2.group(1), m2.group(2)
            obj[_lower_snake(k)] = v.strip()
    return obj

def _try_json_variants(s: str) -> Optional[Any]:
    for t in (s, _fix_jsonish(s)):
        try:
            return json.loads(t)
        except Exception:
            pass
    for frag in _balanced_json_candidates(s):
        for t in (frag, _fix_jsonish(frag)):
            try:
                return json.loads(t)
            except Exception:
                continue
    return None

def _extract_json_permissive(text: str, *, system_text: str, target: str) -> Optional[Dict[str, str]]:
    s = _json_unescape_if_needed(_strip_code_fences(text))
    parsed = _try_json_variants(s)
    candidates: List[Dict[str, Any]] = []

    if isinstance(parsed, dict):
        candidates.append(parsed)
        for v in parsed.values():
            if isinstance(v, dict): candidates.append(v)
            if isinstance(v, list):
                for it in v:
                    if isinstance(it, dict): candidates.append(it)
    elif isinstance(parsed, list):
        for it in parsed:
            if isinstance(it, dict): candidates.append(it)

    if not candidates:
        y = _parse_yamlish(s)
        if y: candidates.append(y)

    last_command, result_summary = _extract_context(system_text)

    if candidates:
        best, best_score = None, -1
        for d in candidates:
            sc = _score_dict(d)
            if sc > best_score:
                best, best_score = d, sc
        norm = _normalize_fields(best or {})
        return _finalize_plan(norm, last_command=last_command, result_summary=result_summary, target=target)

    m = _CMD_LINE_RE.search(s)
    cmd = m.group(0).strip() if m else _escalate_from_summary(result_summary, target, last_command)
    return {
        "rationale": "Interpreted a non-standard response; proceeding with best-effort next action.",
        "command": cmd,
        "expected_outcome": "Useful output to guide the following step.",
        "next_steps": "If this fails, adjust timing/technique or pivot to service-specific enumeration.",
    }

# ---------------- Execution/result helpers ----------------
def _truthy_error(err: Any) -> bool:
    if err is None: return False
    if isinstance(err, (bool, int)) and err == 0: return False
    if isinstance(err, str) and err.strip() == "": return False
    return True

def _norm_result(data: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {"success": False, "exit_code": 1, "stderr": "Bad response type"}
    success = data.get("success", data.get("ok"))
    exit_code = data.get("exit_code", data.get("return_code"))
    if success is None and exit_code is not None:
        try: success = (int(exit_code) == 0)
        except Exception: success = False
    stdout = data.get("stdout") or data.get("out") or data.get("output") or ""
    stderr = data.get("stderr") or data.get("error_output") or ""
    exec_time = data.get("execution_time") or data.get("duration") or 0
    timed_out = bool(data.get("timed_out"))
    return {
        "success": bool(success),
        "exit_code": exit_code if exit_code is not None else (0 if success else 1),
        "stdout": stdout, "stderr": stderr,
        "execution_time": exec_time, "timed_out": timed_out,
        "_raw": data,
    }

# ---------------- Client ----------------
class Client:
    def __init__(self, kali_url: str, model: str, *, timeout: int = 2000, debug_json: bool = False, dry_run: bool = False, trace: bool = False, max_steps: Optional[int] = None):
        self.kali_url = kali_url.rstrip("/")
        self.model = model
        self.timeout = timeout  # seconds for ALL HTTP calls (except health 10s)
        self.session_id: Optional[int] = None
        self.thread_id: Optional[int] = None
        self.tools_info = ""
        self.available: Dict[str, Any] = {}
        self.debug_json = debug_json
        self.dry_run = dry_run
        self.trace = trace
        self.max_steps = max_steps
        self.target: str = ""
        self._fetch_tools()

    # ----- HTTP -----
    def _api(self, method: str, path: str, data: dict | None = None) -> Dict[str, Any]:
        url = f"{self.kali_url}{path}"
        try:
            if self.trace:
                print(f"\n[TRACE] {method} {url}")
                if data is not None:
                    print("[TRACE] payload:", json.dumps(data, ensure_ascii=False)[:2000])
            if method == "GET":
                r = requests.get(url, timeout=self.timeout)
            else:
                r = requests.post(url, json=(data or {}), timeout=self.timeout)
            if self.trace:
                print("[TRACE] status:", r.status_code)
                try: print("[TRACE] response:", r.json())
                except Exception: print("[TRACE] response(text):", r.text[:2000])
            try:
                j = r.json()
                if isinstance(j, dict):
                    j.setdefault("status", r.status_code)
                return j
            except Exception:
                return {"raw_text": r.text, "status": r.status_code}
        except Exception as e:
            return {"error": f"API request failed: {e}"}

    # ----- Tools & presets -----
    def _fetch_tools(self) -> None:
        if self.dry_run:
            self.tools_info = "Dry-run: tools info unavailable (skipped network)"
            print("🔧 Loaded 0 available tools (dry-run)")
            return
        info = self._api("GET", "/api/tools")
        if "error" in info or not isinstance(info, dict):
            print("⚠  Tools fetch failed or not supported.")
            self.tools_info = "Tools information not available"
            return
        self.available = info.get("tools", {}) or {}
        lines = []
        for name, meta in self.available.items():
            if meta.get("available"):
                presets = meta.get("presets", [])
                lines.append(
                    f"- {name}: {meta.get('description','')}"
                    + (f" (presets: {', '.join(presets)})" if presets else "")
                )
        self.tools_info = "\n".join(lines)
        print(f"🔧 Loaded {sum(1 for t in self.available.values() if t.get('available'))} available tools")

    def presets_for(self, tool: str) -> List[str]:
        if self.dry_run: return []
        data = self._api("GET", f"/api/tools/{tool}/presets")
        if "error" in data or not isinstance(data, dict): return []
        if isinstance(data.get("presets"), dict): return list(data["presets"].keys())
        return list((data.get("presets", []) or []))

    # ----- LLM -----
    def _llm_params(self) -> Dict[str, Any]:
        return {"model": self.model, "max_tokens": 800, "temperature": 0.1, "response_format": {"type": "json_schema", "json_schema": JSON_SCHEMA}}

    def ask_llm_backend(self, system: str, user: str) -> str:
        payload = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": 800,
            "temperature": 0.1,
            "response_format": {"type": "json_schema", "json_schema": JSON_SCHEMA},
        }
        if self.trace:
            print("\n[TRACE] POST /api/llm (old)", json.dumps(payload)[:1200])
        try:
            r = requests.post(f"{self.kali_url}/api/llm", json=payload, timeout=self.timeout)
            if self.trace:
                print("[TRACE] /api/llm(old) status:", r.status_code)
                try: print("[TRACE] /api/llm(old) resp:", r.json())
                except Exception: print("[TRACE] /api/llm(old) text:", r.text[:2000])
            if r.status_code == 200:
                data = r.json()
                if isinstance(data.get("response"), dict):
                    return (data["response"].get("content") or "").strip()
                return (data.get("raw", {}).get("choices", [{}])[0].get("message", {}).get("content", "")).strip()
            fb = self._local_plan(system, user); return json.dumps(fb)
        except Exception:
            fb = self._local_plan(system, user); return json.dumps(fb)

    def ask_json(self, system: str, user: str) -> Dict[str, str]:
        raw = self.ask_llm_backend(system, user)
        plan = _extract_json_permissive(raw, system_text=system, target=self.target)
        if plan: return plan
        if self.debug_json or os.getenv("DEBUG_JSON") == "1":
            print("\n[DEBUG] Raw LLM output:\n" + "-" * 40 + f"\n{raw}\n" + "-" * 40)
        return self._local_plan(system, user)

    # ----- Local fallback planner -----
    def _local_plan(self, system: str, user: str) -> Dict[str, str]:
        tgt = self.target.strip() or "<target>"
        last_cmd, result_summary = _extract_context(system)
        if "Suggest the first command" in user:
            return {
                "rationale": "Start with fast, low-noise recon.",
                "command": f"nmap --preset quick-scan {tgt}",
                "expected_outcome": "Top ports and services.",
                "next_steps": "If none found, escalate to -Pn full TCP; else run -sV -sC on found ports.",
            }
        cmd = _escalate_from_summary(result_summary, tgt, last_cmd)
        return {
            "rationale": "Choose the next best recon step based on previous outcome.",
            "command": cmd,
            "expected_outcome": "Discover actionable ports/services.",
            "next_steps": "Enumerate discovered services; adjust timing if filtered.",
        }

    # ----- Session/validate/exec -----
    def create_session(self, goal: str, target: str) -> bool:
        if self.dry_run:
            print("📝 Session: DRY-RUN (no server calls)"); self.target = target; return True
        data = self._api("POST", "/api/sessions", {"title": f"{goal} | {target}" if target else goal})
        if "error" in data: print(f"❌ Session create failed: {data['error']}"); return False
        self.session_id, self.thread_id, self.target = data.get("session_id"), data.get("thread_id"), target
        if not (self.session_id and self.thread_id): print("❌ Session create failed: invalid response"); return False
        print(f"📝 Session: {self.session_id} | Thread: {self.thread_id}"); return True

    def validate(self, cmd: str) -> Dict[str, Any]:
        if self.dry_run: return {"valid": True, "reason": "dry-run"}
        res = self._api("POST", "/api/validate", {"command": cmd})
        if "error" in res or not isinstance(res, dict) or "valid" not in res:
            return {"valid": True, "reason": "validator not available"}
        return res

    def _exec_try_variants(self, tool: str, cmd: str) -> Dict[str, Any]:
        variants = [
            ("POST", "/api/command", {"command": cmd, **({"session_id": self.session_id} if self.session_id else {})}),
            ("POST", "/api/exec",    {"session_id": self.session_id, "thread_id": self.thread_id, "parent_message_id": None, "tool_name": tool, "command": cmd}),
            ("POST", "/api/exec",    {"session_id": self.session_id, "thread_id": self.thread_id, "tool": tool, "command": cmd}),
            ("POST", "/api/exec",    {"session_id": self.session_id, "thread_id": self.thread_id, "tool": tool, "args": {"command": cmd}}),
        ]
        last = {}
        for method, path, payload in variants:
            res = self._api(method, path, payload)
            if self.trace:
                print(f"[TRACE] tried {path} -> status={res.get('status')} keys={list(res.keys()) if isinstance(res, dict) else type(res)}")
            if not isinstance(res, dict):
                continue
            status = res.get("status")
            if status and int(status) != 200:
                continue
            if set(res.keys()) == {"detail", "status"} and "Not Found" in str(res.get("detail")):
                continue
            if any(k in res for k in ("success", "stdout", "stderr", "return_code", "exit_code", "output")):
                return _norm_result(res)
            last = res
        return _norm_result(last if isinstance(last, dict) else {"success": False, "stderr": "Exec failed"})

    def _maybe_expand_preset(self, cmd: str) -> str:
        m = re.search(r"^\s*(\S+)\s+.*--preset\s+(\S+)\b", cmd)
        if not m: return cmd
        tool, preset = m.group(1), m.group(2)
        try:
            data = self._api("GET", f"/api/tools/{tool}/presets")
            mapping = (data.get("presets", {}) or {}) if isinstance(data, dict) else {}
            flags = mapping.get(preset)
            if not flags: return cmd
            return re.sub(r"--preset\s+\S+\b", flags, cmd)
        except Exception:
            return cmd

    def run(self, cmd: str) -> Dict[str, Any]:
        if self.dry_run: return {"success": True, "exit_code": 0, "stdout": "", "stderr": "", "execution_time": 0}
        tool = (cmd.split() or [""])[0]
        cmd_expanded = self._maybe_expand_preset(cmd)
        if self.trace and cmd_expanded != cmd:
            print(f"[TRACE] preset expanded: {cmd}  ->  {cmd_expanded}")
        return self._exec_try_variants(tool, cmd_expanded)

    # ----- Summaries & display -----
    def _summarize(self, res: Dict[str, Any]) -> str:
        if _truthy_error(res.get("error")):
            return f"Error: {res['error']}"
        parts = [f"Success: {res.get('success', False)}",
                 f"Return code: {res.get('exit_code') if 'exit_code' in res else res.get('return_code')}",
                 f"Execution time: {res.get('execution_time', 0)}s"]
        if res.get("timed_out"): parts.append("TIMED OUT")
        out = (res.get("stdout") or "").strip()
        if out: parts.append(f"Key output: {out[:500]}{'...' if len(out) > 500 else ''}")
        err = (res.get("stderr") or "").strip()
        if err and not res.get("success", True): parts.append(f"Errors: {err[:200]}{'...' if len(err) > 200 else ''}")
        return " | ".join(parts)[:1200]

    def display(self, res: Dict[str, Any]) -> None:
        print("\n" + "=" * 60)
        if _truthy_error(res.get("error")):
            print("❌", str(res.get("error")).strip())
            if self.trace and res.get("_raw"): print("\n[TRACE] raw:", res["_raw"])
            return
        success = bool(res.get("success", True if res.get("exit_code", 0) == 0 else False))
        status = "✅" if success else "❌"
        exec_time = res.get("execution_time", 0) or 0
        try: exec_time = float(exec_time)
        except Exception: exec_time = 0.0
        rc = res.get("exit_code") if "exit_code" in res else res.get("return_code")
        print(f"{status} Completed in {exec_time:.2f}s | rc={rc}")
        if res.get("timed_out"): print("⏱  Timed out (partial)")
        out = (res.get("stdout") or "")
        if out:
            print("\n📤 Output:"); print("-" * 40)
            print(out[:2000] + (f"\n... [truncated {len(out)-2000}]" if len(out) > 2000 else ""))
        err = (res.get("stderr") or "")
        if err and not success:
            print("\n📛 Errors:"); print("-" * 40)
            print(err[:1000] + ("... [truncated]" if len(err) > 1000 else ""))

    # ----- Interactive loop -----
    def interactive(self) -> None:
        if not self.dry_run:
            try:
                # Keep health short so CLI doesn't hang
                r = requests.get(f"{self.kali_url}/health", timeout=10)
                try:
                    h = r.json()
                    msg = "OK" if (isinstance(h, dict) and h.get("ok") is True) else h.get("message", "OK")
                except Exception:
                    msg = "OK"
                print(f"✅ Backend: {msg}")
            except Exception as e:
                print(f"❌ Backend not reachable: {e}"); return
        else:
            print("✅ DRY-RUN: skipping backend health check")

        goal = input("🎯 Goal: ").strip()
        if not goal: print("Goal required"); return
        target = input("🎯 Target (IP/domain/URL): ").strip()
        if not self.create_session(goal, target): return

        print(f"\n🚀 Target: {target}\n📋 Goal: {goal}")

        sys = INITIAL_SYSTEM.format(tools_info=self.tools_info or "No tools")
        user = f"Goal: {goal}\nTarget: {target}\n\nSuggest the first command."
        sug = self.ask_json(sys, user)
        step = 1

        while sug:
            print(f"\n🧭 Step {step}")
            print(f"💭 {sug.get('rationale', '')}")
            cmd_raw = sug.get("command", "").strip()
            cmd = re.sub(r"<[^>]+>", target.strip(), cmd_raw) if target else cmd_raw
            print(f"🔧 {cmd}")
            print(f"🎯 {sug.get('expected_outcome', '')}")

            if not cmd:
                print("❌ No command"); break

            v = self.validate(cmd)
            if not v.get("valid", True):
                reason = v.get("reason", "Unknown")
                print(f"⚠  Rejected: {reason}")
                sys2 = FOLLOWUP_SYSTEM.format(last_command=cmd, result_summary=f"Validation failed: {reason}")
                sug = self.ask_json(sys2, "Suggest an alternative.")
                step += 1
                if self.max_steps and step > self.max_steps: print("⏹  Reached max steps."); break
                continue

            if not self.dry_run:
                tool = cmd.split()[0]
                presets = self.presets_for(tool)
                if presets: print(f"💡 Presets: {', '.join(presets[:5])}")
                print(f"\n⚡ Executing: {cmd}")
                res = self.run(cmd)
                self.display(res)
                summary = self._summarize(res)
            else:
                print("🧪 DRY-RUN: skipping execute")
                summary = "Dry-run: not executed"

            sys3 = FOLLOWUP_SYSTEM.format(last_command=cmd, result_summary=summary)
            sug = self.ask_json(sys3, "Analyze and suggest the next step.")
            step += 1
            if self.max_steps and step > self.max_steps: print("⏹  Reached max steps."); break
            time.sleep(0.3)

# ---------------- CLI ----------------
def main() -> None:
    ap = argparse.ArgumentParser(description="Chat Client (permissive JSON + resilient flow + configurable timeouts)")
    ap.add_argument("--kali-url", default="http://127.0.0.1:5000")
    ap.add_argument("--model", default="gpt-4o")
    ap.add_argument("--timeout", type=int, default=2000, help="HTTP timeout in seconds for API/LLM calls (default: 2000)")
    ap.add_argument("--test-connection", action="store_true")
    ap.add_argument("--debug-json", action="store_true", help="Print raw LLM output when parsing fails")
    ap.add_argument("--dry-run", action="store_true", help="Plan steps without validating or executing commands")
    ap.add_argument("--trace", action="store_true", help="Trace HTTP requests/responses")
    ap.add_argument("--max-steps", type=int, default=None, help="Stop after N planned steps")
    args = ap.parse_args()

    c = Client(args.kali_url, args.model, timeout=args.timeout, debug_json=args.debug_json, dry_run=args.dry_run, trace=args.trace, max_steps=args.max_steps)

    if args.test_connection:
        try:
            payload = {
                "model": args.model,
                "messages": [
                    {"role": "system", "content": "You are a test assistant. RAW JSON ONLY."},
                    {"role": "user", "content": "{\"rationale\":\"x\",\"command\":\"echo test\",\"expected_outcome\":\"ok\",\"next_steps\":\"done\"}"},
                ],
                "max_tokens": 16, "temperature": 0.1,
                "response_format": {"type": "json_schema", "json_schema": JSON_SCHEMA},
            }
            if args.trace: print("\n[TRACE] POST /api/llm (test-connection)", json.dumps(payload))
            r = requests.post(f"{args.kali_url}/api/llm", json=payload, timeout=args.timeout)
            if args.trace:
                print("[TRACE] status:", r.status_code)
                try: print("[TRACE] resp:", r.json())
                except Exception: print("[TRACE] text:", r.text[:2000])
            if r.status_code == 200:
                content = (r.json().get("response") or {}).get("content", "")
                ok = _extract_json_permissive(content, system_text="", target="")
                print("✅ LLM via backend: OK" if ok else "⚠  LLM via backend: parse failed")
            else:
                print(f"⚠  LLM backend non-200 ({r.status_code}). Local planner will be used in session.")
        except Exception as e:
            print(f"⚠  Test failed: {e}. Local planner will be used in session.")
        return

    print("🚀 Enhanced Chat Client (backend mode)")
    print(f"🔧 Backend: {args.kali_url} | 🧠 Model: {args.model} | ⏱ Timeout: {args.timeout}s | 🧪 Dry-run: {'ON' if args.dry_run else 'OFF'} | 🔍 Trace: {'ON' if args.trace else 'OFF'}")
    c.interactive()

if __name__ == "__main__":
    main()
