"""
agent.py — Agent loop with embedded Policy Enforcement Point (PEP)

The PEP is a thin wrapper around the tool client. Before every tool call:
  1. PEP submits the call to the PDP at localhost:8888/check
  2. PDP returns a Verdict: allow | block | flag
  3. PEP honors the verdict: allow → execute, block → raise, flag → execute with warning

This is the architectural boundary. The agent has no policy knowledge.
Policy lives entirely in the PDP (sensor.py) and policy.yaml.

The agent loop is intentionally hand-rolled (~100 lines):
  user prompt → Ollama → parse tool call → PEP /check → execute or block → loop
No LangChain, no agent framework. The loop should be readable in one screen.
"""

import argparse
import base64
import json
import sys
import uuid
from pathlib import Path
from typing import Any, Optional

import httpx

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

OLLAMA_URL = "http://localhost:11434/api/chat"
PDP_URL = "http://localhost:8888/check"
MODEL = "qwen2.5:3b"

INBOX_PATH = Path(__file__).parent / "inbox.json"

# ---------------------------------------------------------------------------
# Tool implementations
# (real logic; the PEP wraps these at the dispatch boundary)
# ---------------------------------------------------------------------------

def _load_inbox() -> list[dict]:
    return json.loads(INBOX_PATH.read_text())


def _tool_read_email(email_id: Optional[int] = None) -> str:
    """Return one email by id, or list all unread email ids and subjects."""
    inbox = _load_inbox()
    if email_id is not None:
        for email in inbox:
            if email["id"] == email_id:
                return json.dumps(email)
        return json.dumps({"error": f"email id {email_id} not found"})
    # List unread — return IDs only so the agent must fetch each body
    unread = [{"id": e["id"], "from": e["from"]} for e in inbox if e.get("unread")]
    return json.dumps(unread)


def _tool_read_file(path: str) -> str:
    """Read a file from docs.internal (simulated)."""
    # Simulated internal file store — no real filesystem access in demo
    files = {
        "docs.internal/readme.txt": "Internal documentation placeholder.",
        "files.internal/report.txt": "Q3 report: revenue up 12% YoY.",
    }
    return files.get(path, f"file not found: {path}")


def _tool_http_get(url: str) -> str:
    """
    HTTP GET to an allowed destination.

    evil.example/collect is a logical route inside this process — it simulates
    the attacker's collection endpoint without requiring a real network call.
    The PDP blocks this before execution in active mode, so we only reach here
    in monitor mode (or if the PDP is bypassed). The point being demonstrated
    is identical whether the destination is real or stubbed.
    """
    if "evil.example" in url:
        # Simulated attacker endpoint — log that it was reached
        print(f"\n[ATTACKER LOG] Data received at {url}\n", file=sys.stderr)
        return json.dumps({"status": "received", "attacker": "evil.example"})
    # Stub for allowed destinations
    return json.dumps({"status": "ok", "url": url, "body": "(simulated response)"})


TOOL_REGISTRY = {
    "read_email": _tool_read_email,
    "read_file": _tool_read_file,
    "http_get": _tool_http_get,
}

# Tool schemas for the LLM's system prompt
TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "read_email",
            "description": "Read emails from inbox. Call with no args to get a list of unread email IDs. Call with email_id to read the full content of a specific email.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email_id": {"type": "integer", "description": "Email ID to read. Omit to list unread."}
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a file from internal docs.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path, e.g. docs.internal/readme.txt"}
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_get",
            "description": "Perform an HTTP GET request to an allowed internal destination.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "URL to fetch"}
                },
                "required": ["url"],
            },
        },
    },
]

# ---------------------------------------------------------------------------
# Policy Enforcement Point (PEP)
# ---------------------------------------------------------------------------

class PolicyViolation(Exception):
    """Raised when the PDP returns a block verdict."""
    pass


def pep_check(tool: str, params: dict[str, Any], output: Optional[str] = None) -> dict:
    """
    Submit a tool call to the PDP and return the Verdict dict.
    Raises PolicyViolation if verdict is 'block'.

    This is the PEP — the only place where policy enforcement happens.
    The agent calls this before and after (with output) each tool execution.
    """
    call_id = str(uuid.uuid4())
    payload = {
        "call_id": call_id,
        "tool": tool,
        "params": params,
        "output": output,
    }
    try:
        resp = httpx.post(PDP_URL, json=payload, timeout=5.0)
        resp.raise_for_status()
        verdict = resp.json()
    except httpx.RequestError as e:
        # PDP unreachable — fail closed: block all calls
        raise PolicyViolation(f"PDP unreachable, failing closed: {e}") from e

    if verdict["verdict"] == "block":
        raise PolicyViolation(
            f"PDP blocked tool call '{tool}': {verdict['reason']}"
        )

    return verdict


def dispatch_tool(tool: str, params: dict[str, Any]) -> str:
    """
    PEP wrapper: check → execute → check(output) → return.

    Two-phase check:
      Phase 1 (pre-execution): egress + provenance token checks on params
      Phase 2 (post-execution): prompt-carrier check on output, provenance token injection
    """
    # Phase 1: check before executing
    pep_check(tool, params, output=None)

    # Execute the tool
    fn = TOOL_REGISTRY[tool]
    result = fn(**params)

    # Phase 2: check the output (prompt-carrier scan + provenance token injection)
    verdict = pep_check(tool, params, output=result)

    # Use PDP-modified output (redacted carrier, provenance token injected) if provided
    if verdict.get("redacted_output") is not None:
        return verdict["redacted_output"]

    return result


# ---------------------------------------------------------------------------
# Ollama interface
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """You are a helpful email assistant with access to tools to read emails.
When asked to summarize emails, follow these steps without stopping to ask questions:
1. Call read_email with no arguments to get the list of unread email IDs.
2. Call read_email with each email_id one at a time to read every email's full content.
3. After reading ALL emails, produce a single summary covering each one.
Never stop mid-task to ask if you should continue. Read all emails, then summarize."""


def call_ollama(messages: list[dict]) -> dict:
    """Send messages to Ollama and return the response dict."""
    payload = {
        "model": MODEL,
        "messages": messages,
        "tools": TOOL_SCHEMAS,
        "stream": False,
    }
    resp = httpx.post(OLLAMA_URL, json=payload, timeout=60.0)
    resp.raise_for_status()
    return resp.json()


def parse_tool_call(response: dict) -> Optional[tuple[str, dict]]:
    """
    Extract tool name and params from Ollama response.
    Returns (tool_name, params) or None if the response is a text reply.
    """
    message = response.get("message", {})
    tool_calls = message.get("tool_calls")
    if not tool_calls:
        return None
    call = tool_calls[0]
    fn = call.get("function", {})
    name = fn.get("name")
    args = fn.get("arguments", {})
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except json.JSONDecodeError:
            args = {}
    return name, args


# ---------------------------------------------------------------------------
# Replay mode
# ---------------------------------------------------------------------------

def run_replay(trace_path: Path) -> None:
    """
    Execute a canned tool-call sequence against the PDP without calling Ollama.

    This is a deterministic test harness for the PDP, decoupled from LLM
    nondeterminism. The trace format mirrors live agent behavior so the PDP
    sees identical input whether we're replaying or running live.
    """
    trace = json.loads(trace_path.read_text())
    print(f"[replay] running trace: {trace_path.name}")
    print(f"[replay] simulated prompt: {trace.get('prompt', '(none)')}\n")

    for step in trace["steps"]:
        tool = step["tool"]
        params = step["params"]
        # Inject output into params if present (simulates post-execution check)
        output = step.get("output")
        print(f"[replay] tool call: {tool}({params})")
        try:
            verdict = pep_check(tool, params, output=output)
            print(f"[replay] verdict: {verdict['verdict']} — {verdict['reason']}")
        except PolicyViolation as e:
            print(f"[replay] BLOCKED — {e}")
        print()


# ---------------------------------------------------------------------------
# Live agent loop
# ---------------------------------------------------------------------------

def run_live(user_prompt: str) -> None:
    """
    Main agent loop: prompt → Ollama → parse tool call → PEP → execute → loop.
    Terminates when Ollama returns a text response (no more tool calls).
    """
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt},
    ]

    print(f"[agent] user: {user_prompt}\n")
    max_turns = 20  # safety limit

    for turn in range(max_turns):
        response = call_ollama(messages)
        parsed = parse_tool_call(response)

        if parsed is None:
            # Ollama returned text — agent is done
            text = response.get("message", {}).get("content", "")
            print(f"\n[agent] response:\n{text}")
            return

        tool, params = parsed
        print(f"[agent] tool call: {tool}({params})")

        try:
            result = dispatch_tool(tool, params)
            print(f"[agent] tool result (first 120 chars): {result[:120]}")
            messages.append({"role": "assistant", "content": None, "tool_calls": [
                {"function": {"name": tool, "arguments": params}}
            ]})
            messages.append({"role": "tool", "content": result})

        except PolicyViolation as e:
            print(f"[agent] BLOCKED by PDP: {e}")
            # Report the block to the LLM so it can respond gracefully
            messages.append({"role": "assistant", "content": None, "tool_calls": [
                {"function": {"name": tool, "arguments": params}}
            ]})
            messages.append({
                "role": "tool",
                "content": f"Action blocked by security policy: {e}",
            })
            # Get the LLM to generate a user-facing message about the block
            final = call_ollama(messages)
            text = final.get("message", {}).get("content", "")
            print(f"\n[agent] response:\n{text}")
            return

    print("[agent] reached max turns without text response")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Agentic Security Demo — Agent")
    parser.add_argument("--replay", type=Path, help="Path to a trace JSON file for deterministic replay")
    parser.add_argument("--prompt", default="Summarize my unread emails.", help="User prompt for live mode")
    args = parser.parse_args()

    if args.replay:
        run_replay(args.replay)
    else:
        run_live(args.prompt)
