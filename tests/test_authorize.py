from __future__ import annotations

from mcp_atsa_admission import AuditLog, authorize_tool, decide_tool


def test_allowlisted_tool_is_true(allow_list):
    assert authorize_tool("weather.internal", "get_forecast", allow_list) is True
    assert authorize_tool("weather.internal", "get_alerts", allow_list) is True


def test_unknown_tool_is_false_before_dispatch(allow_list):
    assert authorize_tool("weather.internal", "delete_account", allow_list) is False


def test_unknown_server_is_false(allow_list):
    assert authorize_tool("evil.example", "get_forecast", allow_list) is False


def test_empty_names_denied(allow_list):
    assert authorize_tool("", "get_forecast", allow_list) is False
    assert authorize_tool("weather.internal", "", allow_list) is False


def test_decide_tool_explains_deny(allow_list):
    decision = decide_tool("weather.internal", "delete_account", allow_list)
    assert decision.verdict == "deny"
    assert decision.allowed is False
    assert any(r.code == "tool_not_allowlisted" for r in decision.reasons)
    assert "get_forecast" in (decision.reasons[0].detail or "")


def test_decide_tool_writes_audit(allow_list):
    audit = AuditLog()
    decide_tool("weather.internal", "get_forecast", allow_list, audit=audit)
    decide_tool("weather.internal", "delete_account", allow_list, audit=audit)
    assert [e["event"] for e in audit.entries] == ["mcp.tool.allow", "mcp.tool.deny"]
    assert audit.verify_chain() is True


def test_mapping_allow_list_accepted():
    raw = {"servers": {"weather.internal": ["get_forecast"]}}
    assert authorize_tool("weather.internal", "get_forecast", raw) is True
    assert authorize_tool("weather.internal", "get_alerts", raw) is False
