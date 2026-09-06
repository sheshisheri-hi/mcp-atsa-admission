from __future__ import annotations

import io
import json
from pathlib import Path

from mcp_atsa_admission.cli import main

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def test_cli_valid_admit(capsys):
    code = main([str(FIXTURES / "clearance_valid.json")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "admit"
    assert payload["server_id"] == "weather.internal"


def test_cli_forged_exits_2(capsys):
    code = main([str(FIXTURES / "clearance_forged.json")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["verdict"] == "deny"
    assert any(r["code"] == "bad_signature" for r in payload["reasons"])


def test_cli_admit_subcommand(capsys):
    code = main(["admit", str(FIXTURES / "clearance_expired.json")])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert any(r["code"] == "expired" for r in payload["reasons"])


def test_cli_tool_allow(capsys):
    code = main(["tool", "weather.internal", "get_forecast"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "allow"


def test_cli_tool_deny(capsys):
    code = main(["tool", "weather.internal", "delete_account"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert payload["verdict"] == "deny"
    assert any(r["code"] == "tool_not_allowlisted" for r in payload["reasons"])


def test_cli_missing_file(capsys):
    code = main(["/tmp/does-not-exist-mcp-atsa.json"])
    assert code == 1
    assert "error:" in capsys.readouterr().err


def test_cli_stdin(monkeypatch, capsys):
    monkeypatch.setattr(
        "mcp_atsa_admission.cli.sys.stdin",
        io.StringIO((FIXTURES / "clearance_valid.json").read_text(encoding="utf-8")),
    )
    code = main(["-"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["verdict"] == "admit"


def test_cli_expected_server_override_denies(capsys):
    code = main(
        [
            str(FIXTURES / "clearance_valid.json"),
            "--expected-server-id",
            "other.internal",
        ]
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 2
    assert any(r["code"] == "server_id_mismatch" for r in payload["reasons"])


def test_cli_audit_flag(tmp_path, capsys):
    path = tmp_path / "audit.jsonl"
    code = main(["--audit", str(path), str(FIXTURES / "clearance_valid.json")])
    assert code == 0
    json.loads(capsys.readouterr().out)
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["event"] == "mcp.connect.admit"
