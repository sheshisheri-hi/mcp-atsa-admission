from __future__ import annotations

from mcp_atsa_admission.audit import GENESIS_PREV, AuditLog


def test_empty_chain_is_valid():
    assert AuditLog().verify_chain() is True
    assert AuditLog().head == GENESIS_PREV


def test_hash_chain_links_entries():
    log = AuditLog()
    first = log.append("mcp.connect.admit", verdict="admit", server_id="weather.internal")
    second = log.append(
        "mcp.tool.deny",
        verdict="deny",
        server_id="weather.internal",
        tool_name="delete_account",
        reason_codes=["tool_not_allowlisted"],
    )
    assert first["prev"] == GENESIS_PREV
    assert second["prev"] == first["hash"]
    assert first["hash"] != second["hash"]
    assert log.verify_chain() is True


def test_tampered_entry_breaks_chain():
    log = AuditLog()
    log.append("mcp.connect.admit", verdict="admit", server_id="weather.internal")
    log.append("mcp.tool.allow", verdict="allow", server_id="weather.internal", tool_name="get_forecast")
    log.entries[0]["verdict"] = "deny"
    assert log.verify_chain() is False


def test_persists_jsonl(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path=path)
    log.append("mcp.connect.deny", verdict="deny", server_id="evil.example")
    reloaded = AuditLog(path=path)
    assert len(reloaded.entries) == 1
    assert reloaded.verify_chain() is True
    assert reloaded.entries[0]["event"] == "mcp.connect.deny"
