#!/usr/bin/env python3
"""
Simple Chat Interface for Offline LLM + Kali Tools (Complete)
- Enforces one-command-at-a-time via strict JSON schema
- Uses Ollama format='json' and robust JSON extraction fallback
- Validates with /api/validate before execution
- Feeds results back to LLM for the next suggestion
"""

import requests, json, re, argparse
from typing import Dict, Any, Optional

SUGGESTION_SYSTEM = (
    "You are a cybersecurity assistant with access to Kali Linux tools via an HTTP API.\n"
    "Return ONLY valid minified JSON with exactly these keys:\n"
    '{"rationale":"string","command":"string","expected_signal":"string","fallback":"string"}\n'
    "No extra text or code fences. Only suggest actions for systems the user is authorized to test."
)
FOLLOWUP_SYSTEM = (
    "Based on the last command result, return ONLY valid minified JSON with the same schema. "
    "No extra text."
)

def _extract_first_json(s: str) -> Optional[dict]:
    try:
        return json.loads(s)
    except Exception:
        pass
    m = re.search(r'(\{.*\})', s, re.DOTALL)
    if not m:
        return None
    frag = m.group(1)
    depth = 0; end = 0
    for i,ch in enumerate(frag):
        if ch == '{': depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                end = i+1; break
    if end:
        try: return json.loads(frag[:end])
        except Exception: return None
    return None

class KaliChatBot:
    def __init__(self, llm_url: str = "http://localhost:11434", kali_api_url: str = "http://127.0.0.1:5000", model: str = "llama3.1:8b"):
        self.llm_url = llm_url
        self.kali_api_url = kali_api_url
        self.model = model

    def _ask_json(self, system: str, user: str) -> Optional[Dict[str, Any]]:
        try:
            if "11434" in self.llm_url:
                r = requests.post(
                    f"{self.llm_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": f"{system}\n\n{user}",
                        "stream": False,
                        "options": {"temperature": 0.1, "top_p": 0.9},
                        "format": "json"
                    },
                    timeout=180
                )
                r.raise_for_status()
                raw = r.json().get("response","").strip()
            else:
                r = requests.post(
                    f"{self.llm_url}/v1/chat/completions",
                    json={
                        "model": self.model,
                        "messages": [
                            {"role":"system","content":system},
                            {"role":"user","content":user}
                        ],
                        "temperature": 0.1
                    },
                    headers={"Content-Type":"application/json"},
                    timeout=180
                )
                r.raise_for_status()
                raw = r.json()["choices"][0]["message"]["content"].strip()

            data = _extract_first_json(raw)
            if data is not None:
                return data

            # Retry forcing JSON only
            if "11434" in self.llm_url:
                r2 = requests.post(
                    f"{self.llm_url}/api/generate",
                    json={
                        "model": self.model,
                        "prompt": "Return ONLY valid JSON object now.",
                        "stream": False,
                        "options": {"temperature": 0.0},
                        "format": "json"
                    },
                    timeout=60
                )
                raw2 = r2.json().get("response","").strip()
            else:
                r2 = requests.post(
                    f"{self.llm_url}/v1/chat/completions",
                    json={
                        "model": self.model,
                        "messages": [{"role":"system","content":"Return ONLY valid JSON object now."}],
                        "temperature": 0.0
                    },
                    headers={"Content-Type":"application/json"},
                    timeout=60
                )
                raw2 = r2.json()["choices"][0]["message"]["content"].strip()
            return _extract_first_json(raw2)
        except Exception as e:
            print(f"❌ Error communicating with LLM or parsing JSON: {e}")
            return None

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        try:
            r = requests.post(f"{self.kali_api_url}{path}", json=payload, timeout=360)
            r.raise_for_status()
            return r.json()
        except requests.HTTPError as he:
            try:
                return r.json()
            except Exception:
                return {"error": f"HTTP error: {he}"}
        except Exception as e:
            return {"error": f"POST {path} failed: {e}"}

    def validate(self, command: str) -> Dict[str, Any]:
        return self._post("/api/validate", {"command": command})

    def run(self, command: str) -> Dict[str, Any]:
        return self._post("/api/command", {"command": command})

    def interactive(self):
        print("🤖 Kali + Offline LLM (single-step recommender)")
        goal = input("🎯 Goal: ").strip()
        if not goal:
            print("No goal. Bye.")
            return

        step = 1
        suggestion = self._ask_json(SUGGESTION_SYSTEM, f"User goal: {goal}. Propose exactly ONE command as per schema.")
        while True:
            if suggestion is None:
                print("❌ LLM did not return valid JSON. Abort.")
                return
            cmd = (suggestion.get("command") or "").strip()
            print(f"\n🧭 Step {step} rationale: {suggestion.get('rationale','(none)')}")
            print(f"📝 Proposed command: {cmd}")
            print(f"🔎 Expect: {suggestion.get('expected_signal','(not provided)')}")

            v = self.validate(cmd)
            if not v.get("valid", False):
                print(f"⚠️  Rejected by validator: {v.get('reason')}")
                suggestion = self._ask_json(FOLLOWUP_SYSTEM, f"Previous command rejected: {v.get('reason')}. Goal: {goal}. Propose ONE alternative.")
                continue

            choice = input("Type 'run' to execute, 'skip' for another suggestion, or 'quit': ").strip().lower()
            if choice == "quit": return
            if choice == "skip":
                suggestion = self._ask_json(FOLLOWUP_SYSTEM, f"User skipped. Goal: {goal}. Propose ONE different command.")
                continue
            if choice != "run":
                print("Unknown option. Asking for a new suggestion.")
                suggestion = self._ask_json(FOLLOWUP_SYSTEM, f"Goal: {goal}. Propose ONE command.")
                continue

            print(f"\n🔧 Running: {cmd}")
            result = self.run(cmd)
            if "error" in result:
                print(f"❌ Error: {result['error']}")
            else:
                print(f"✅ Success: {result.get('success')} | Exit: {result.get('return_code')} | Timed out: {result.get('timed_out')}")
                if result.get("stdout"): print("\n📤 STDOUT (first 4000 chars):\n" + (result["stdout"][:4000]))
                if result.get("stderr"): print("\n📛 STDERR (first 2000 chars):\n" + (result["stderr"][:2000]))

            summary = json.dumps({
                "return_code": result.get("return_code"),
                "timed_out": result.get("timed_out"),
                "success": result.get("success"),
                "stdout_preview": (result.get("stdout") or "")[:2000],
                "stderr_preview": (result.get("stderr") or "")[:1000]
            })
            suggestion = self._ask_json(FOLLOWUP_SYSTEM, f"Goal: {goal}\nLast command: {cmd}\nResult: {summary}\nPropose ONE next command.")
            step += 1

def main():
    p = argparse.ArgumentParser(description="Kali Linux + Offline LLM Chat (Complete)")
    p.add_argument("--llm-url", default="http://localhost:11434", help="LLM API URL")
    p.add_argument("--kali-url", default="http://127.0.0.1:5000", help="Kali API server URL")
    p.add_argument("--model", default="llama3.1:8b", help="Model name to use")
    a = p.parse_args()
    print(f"🚀 LLM: {a.llm_url} ({a.model})  🔧 API: {a.kali_url}")
    KaliChatBot(a.llm_url, a.kali_url, a.model).interactive()

if __name__ == "__main__":
    main()
