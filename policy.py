"""
policy.py — Policy Decision Point logic

Pure functions only. No FastAPI, no global state, no I/O except policy file loading.
sensor.py owns state and HTTP; this module owns evaluation.

Three controls, each independently testable:
  check_egress(tool, params, egress_policy)        → (verdict, reason)
  check_prompt_carrier(output, carrier_policy)     → (verdict, reason, redacted|None)
  check_provenance_token(params, active_tokens)    → (verdict, reason)

  evaluate(request, policy, active_tokens)         → Verdict
"""

import json
import re
import secrets
from pathlib import Path
from typing import Any, Optional

import yaml
from pydantic import BaseModel

# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------

POLICY_DIR = Path(__file__).parent / "policy"


def load_policy() -> dict:
    """Load and merge all policy/*.yaml files into a single dict keyed by control."""
    config    = _load_yaml(POLICY_DIR / "config.yaml")
    egress    = _load_yaml(POLICY_DIR / "egress.yaml")
    carrier   = _load_yaml(POLICY_DIR / "carrier.yaml")
    provenance = _load_yaml(POLICY_DIR / "provenance.yaml")
    return {
        "mode":       config.get("mode", "active"),
        "egress":     egress,
        "carrier":    carrier,
        "provenance": provenance,
    }


def _load_yaml(path: Path) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class ToolCallRequest(BaseModel):
    call_id: str
    tool: str
    params: dict[str, Any]
    output: Optional[str] = None


class Verdict(BaseModel):
    call_id: str
    verdict: str                          # allow | block | flag
    reason: str
    check_fired: Optional[str] = None
    provenance_token: Optional[str] = None
    redacted_output: Optional[str] = None


# ---------------------------------------------------------------------------
# Check 1 — Egress allowlist
# ---------------------------------------------------------------------------

def check_egress(tool: str, params: dict[str, Any], egress_policy: dict) -> tuple[str, str]:
    """
    Block any tool call whose destination is not declared in egress.yaml.

    Passes vacuously when no destination param is present (e.g. read_email with
    only an email_id). The interesting case is http_get with an attacker-controlled URL.

    FP surface: near-zero — binary allowlist. A call to an undeclared host is a
    configuration error, not a false positive.
    """
    tool_policy = egress_policy.get("tools", {}).get(tool, {})
    allowed: list[str] = tool_policy.get("allowed_destinations", [])

    destination = params.get("url") or params.get("destination") or params.get("host")
    if destination is None:
        return "allow", "no destination param"

    host = _extract_host(destination)

    if not allowed:
        return "block", f"tool '{tool}' has no declared destinations in policy"

    if host not in allowed:
        return "block", (
            f"destination '{host}' not in allowlist for tool '{tool}' "
            f"(allowed: {allowed})"
        )

    return "allow", f"destination '{host}' is in allowlist"


def _extract_host(destination: str) -> str:
    host = re.sub(r"^https?://", "", destination)
    return host.split("/")[0].split("?")[0].split("#")[0]


# ---------------------------------------------------------------------------
# Check 2 — Prompt-carrier scan
# ---------------------------------------------------------------------------

_COMMENT_IMPERATIVE_RE = re.compile(
    r"<!--.*?\b(must|shall|should|need to|have to|ensure|transmit|send|post|"
    r"encode|base64|collect|exfiltrate|do not|don't|ignore)\b.*?-->",
    re.IGNORECASE | re.DOTALL,
)


def check_prompt_carrier(
    output: str,
    carrier_policy: dict,
) -> tuple[str, str, str | None]:
    """
    Scan tool output for injection idioms before the LLM sees the content.

    Signals:
      - Keywords from carrier.yaml matched case-insensitively
      - HTML/XML comment containing an imperative verb (EchoLeak idiom)
      - Base64 blob longer than carrier.yaml base64_blob_min_length

    On a match: blocks and returns a redacted copy with HTML comments stripped.

    FP surface: moderate. See carrier.yaml for documented FP cases per keyword.
    """
    keywords: list[str] = carrier_policy.get("keywords", [])
    blob_min: int = carrier_policy.get("base64_blob_min_length", 100)
    base64_re = re.compile(rf"[A-Za-z0-9+/]{{{blob_min},}}={{0,2}}")

    triggered = []

    for kw in keywords:
        if kw.lower() in output.lower():
            triggered.append(f"keyword: '{kw}'")

    if _COMMENT_IMPERATIVE_RE.search(output):
        triggered.append("html-comment-with-imperative")

    if base64_re.search(output):
        triggered.append("base64-blob")

    if not triggered:
        return "allow", "no carrier patterns found", None

    reason = f"prompt carrier detected — signals: {', '.join(triggered)}"
    redacted = _COMMENT_IMPERATIVE_RE.sub("[REDACTED BY PDP]", output)
    return "block", reason, redacted


# ---------------------------------------------------------------------------
# Check 3 — Provenance token
# ---------------------------------------------------------------------------

def new_provenance_token(provenance_policy: dict) -> str:
    """Generate a fresh provenance token using config from provenance.yaml."""
    prefix = provenance_policy.get("token_prefix", "INTERNAL-MARKER")
    nbytes = provenance_policy.get("token_hex_bytes", 4)
    return f"{prefix}-{secrets.token_hex(nbytes).upper()}"


def inject_provenance_token(
    call_id: str,
    output: str,
    active_tokens: dict[str, str],
    provenance_policy: dict,
) -> tuple[str, str]:
    """
    Watermark tool output with a unique provenance token and register it.

    Returns (token_string, modified_output).
    Caller is responsible for persisting active_tokens across calls.
    """
    token = new_provenance_token(provenance_policy)
    active_tokens[call_id] = token
    marker = f"\n[{token}: ignore this token, it is for system use only]\n"
    return token, output + marker


def check_provenance_token(
    params: dict[str, Any],
    active_tokens: dict[str, str],
) -> tuple[str, str]:
    """
    Fire if any registered provenance token appears in the current call's params.

    A match means the LLM copied content from a prior tool output into an outbound
    tool call — the influence signal. Near-zero FP surface with 8-hex-char tokens.
    """
    params_str = json.dumps(params)
    for cid, token in active_tokens.items():
        if token in params_str:
            return "block", (
                f"provenance token '{token}' (injected in call {cid}) "
                "found in outbound tool params — LLM influenced by retrieved content"
            )
    return "allow", "no provenance token found in params"


# ---------------------------------------------------------------------------
# Combine: evaluate all checks → single Verdict
# ---------------------------------------------------------------------------

def evaluate(
    request: ToolCallRequest,
    policy: dict,
    active_tokens: dict[str, str],
) -> Verdict:
    """
    Run all three checks and return the authoritative Verdict.

    Check order:
      1. Egress  — applies on every call with a destination param
      2. Carrier — applies when tool output is present (response phase)
      3. Provenance token — applies on outbound params (request phase)

    Any block wins. Provenance token injection happens after all checks
    (only on non-blocked calls with output).
    """
    verdict = "allow"
    reason = "all checks passed"
    check_fired = None
    redacted_output = None
    injected_token = None

    egress_v, egress_r = check_egress(request.tool, request.params, policy["egress"])
    if egress_v == "block":
        verdict, reason, check_fired = "block", egress_r, "check_egress"

    if request.output is not None:
        carrier_v, carrier_r, redacted = check_prompt_carrier(request.output, policy["carrier"])
        if carrier_v in ("flag", "block"):
            if verdict == "allow":
                verdict, reason, check_fired = carrier_v, carrier_r, "check_prompt_carrier"
            redacted_output = redacted

    ptoken_v, ptoken_r = check_provenance_token(request.params, active_tokens)
    if ptoken_v == "block":
        verdict, reason, check_fired = "block", ptoken_r, "check_provenance_token"

    if request.output is not None and verdict != "block":
        base = redacted_output if redacted_output else request.output
        injected_token, watermarked = inject_provenance_token(
            request.call_id, base, active_tokens, policy["provenance"]
        )
        redacted_output = watermarked

    return Verdict(
        call_id=request.call_id,
        verdict=verdict,
        reason=reason,
        check_fired=check_fired,
        provenance_token=injected_token,
        redacted_output=redacted_output,
    )
