"""
sensor.py — Policy Decision Point (PDP) — HTTP layer

Owns: FastAPI app, session state, SSE feed, decision log, /run endpoint.
Delegates all policy evaluation to policy.py.

Routes:
  POST /check   — PEP submits a tool call, receives a Verdict
  POST /mode    — toggle monitor / active
  GET  /mode    — current mode
  GET  /events  — SSE feed for dashboard
  GET  /log     — full decision log as JSON
  GET  /policy  — loaded policy as JSON
  GET  /        — dashboard HTML
  POST /run     — spawn agent.py, stream stdout as SSE (Attack Lab)
"""

import asyncio
import json
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from policy import Verdict, ToolCallRequest, load_policy, evaluate

# ---------------------------------------------------------------------------
# Session state
# ---------------------------------------------------------------------------

_active_provenance_tokens: dict[str, str] = {}
_decision_log: list["DecisionLogEntry"] = []
_sse_queues: list[asyncio.Queue] = []
_mode: str = "active"

LOG_PATH = Path(__file__).parent / "decisions.jsonl"


class DecisionLogEntry(BaseModel):
    timestamp: float
    call_id: str
    tool: str
    params: dict[str, Any]
    verdict: str
    reason: str
    check_fired: Optional[str]
    output_snippet: Optional[str]


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    global _mode
    policy = load_policy()
    _mode = policy.get("mode", "active")
    yield


app = FastAPI(title="Agentic Security PDP", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.post("/check", response_model=Verdict)
async def check(request: ToolCallRequest) -> Verdict:
    policy = load_policy()
    result = evaluate(request, policy, _active_provenance_tokens)

    enforced_verdict = result.verdict
    if _mode == "monitor":
        enforced_verdict = "allow"

    should_log = request.output is not None or result.verdict != "allow"
    if should_log:
        entry = DecisionLogEntry(
            timestamp=time.time(),
            call_id=request.call_id,
            tool=request.tool,
            params=request.params,
            verdict=result.verdict,
            reason=result.reason,
            check_fired=result.check_fired,
            output_snippet=(request.output[:200] if request.output else None),
        )
        _decision_log.append(entry)
        _persist_entry(entry)
        await _broadcast(entry)

    return Verdict(
        call_id=result.call_id,
        verdict=enforced_verdict,
        reason=result.reason if _mode == "active" else f"[monitor] would have: {result.verdict}",
        check_fired=result.check_fired,
        provenance_token=result.provenance_token,
        redacted_output=result.redacted_output if _mode == "active" else None,
    )


@app.post("/mode")
async def set_mode(body: dict) -> dict:
    global _mode
    new_mode = body.get("mode", "active")
    if new_mode not in ("active", "monitor"):
        return {"error": "mode must be 'active' or 'monitor'"}
    _mode = new_mode
    return {"mode": _mode}


@app.get("/mode")
async def get_mode() -> dict:
    return {"mode": _mode}


@app.get("/events")
async def sse_events(request: Request) -> StreamingResponse:
    queue: asyncio.Queue = asyncio.Queue()
    _sse_queues.append(queue)

    async def event_stream():
        for entry in _decision_log:
            yield _format_sse(entry)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    entry = await asyncio.wait_for(queue.get(), timeout=15)
                    yield _format_sse(entry)
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            _sse_queues.remove(queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/log")
async def get_log() -> list[dict]:
    return [e.model_dump() for e in _decision_log]


@app.get("/", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    return HTMLResponse((Path(__file__).parent / "dashboard.html").read_text())


@app.get("/policy")
async def get_policy() -> dict:
    return load_policy()


@app.post("/run")
async def run_agent(body: dict, request: Request) -> StreamingResponse:
    """Spawn agent.py and stream its stdout as SSE for the Attack Lab tab."""
    prompt = body.get("prompt", "Summarize my unread emails.")
    replay = body.get("replay", False)

    agent_path = Path(__file__).parent / "agent.py"
    python = Path(__file__).parent / ".venv" / "bin" / "python"
    if not python.exists():
        python = Path("python3")

    cmd = (
        [str(python), str(agent_path), "--replay", str(Path(__file__).parent / "traces" / "attack.json")]
        if replay
        else [str(python), str(agent_path), "--prompt", prompt]
    )

    async def stream():
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        yield f"data: {json.dumps({'type': 'start', 'prompt': prompt, 'replay': replay})}\n\n"
        async for line in proc.stdout:
            text = line.decode(errors="replace").rstrip()
            if text:
                yield f"data: {json.dumps({'type': 'line', 'text': text})}\n\n"
        await proc.wait()
        yield f"data: {json.dumps({'type': 'done', 'code': proc.returncode})}\n\n"

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _format_sse(entry: DecisionLogEntry) -> str:
    return f"data: {json.dumps(entry.model_dump())}\n\n"


async def _broadcast(entry: DecisionLogEntry) -> None:
    for queue in list(_sse_queues):
        await queue.put(entry)


def _persist_entry(entry: DecisionLogEntry) -> None:
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(entry.model_dump()) + "\n")


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("sensor:app", host="127.0.0.1", port=8888, reload=False)
