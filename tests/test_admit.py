from __future__ import annotations

from datetime import datetime, timezone

from mcp_atsa_admission import AuditLog, Policy, admit_server
from mcp_atsa_admission.crypto import private_from_raw_b64, sign_clearance
from tests.conftest import load_fixture


def _codes(result) -> list[str]:
    return [r.code for r in result.reasons]


def test_valid_clearance_admits(trust_root, policy, clearance_valid):
    result = admit_server(clearance_valid, trust_root, policy)
    assert result.verdict == "admit"
    assert result.admitted is True
    assert result.server_id == "weather.internal"
    assert result.clearance_id == "clr-weather-2026"
    assert result.clearance_hash.startswith("sha256:")
    assert "clearance_ok" in _codes(result)


def test_forged_signature_denied(trust_root, policy):
    result = admit_server(load_fixture("clearance_forged.json"), trust_root, policy)
    assert result.verdict == "deny"
    assert "bad_signature" in _codes(result)


def test_wrong_key_denied(trust_root, policy):
    result = admit_server(load_fixture("clearance_wrong_key.json"), trust_root, policy)
    assert result.verdict == "deny"
    assert "bad_signature" in _codes(result)


def test_expired_denied(trust_root, policy):
    result = admit_server(load_fixture("clearance_expired.json"), trust_root, policy)
    assert result.verdict == "deny"
    assert "expired" in _codes(result)


def test_wrong_server_id_denied(trust_root, policy):
    result = admit_server(load_fixture("clearance_wrong_server.json"), trust_root, policy)
    assert result.verdict == "deny"
    assert "server_id_mismatch" in _codes(result)
    assert result.server_id == "evil.example"


def test_not_yet_valid_denied(trust_root, policy):
    result = admit_server(load_fixture("clearance_not_yet_valid.json"), trust_root, policy)
    assert result.verdict == "deny"
    assert "not_yet_valid" in _codes(result)


def test_sensitivity_denied(trust_root, policy):
    result = admit_server(load_fixture("clearance_confidential.json"), trust_root, policy)
    assert result.verdict == "deny"
    assert "sensitivity_denied" in _codes(result)


def test_tampered_body_breaks_signature(trust_root, policy, clearance_valid):
    tampered = dict(clearance_valid)
    tampered["server_id"] = "weather.internal.evil"
    result = admit_server(tampered, trust_root, policy)
    assert result.verdict == "deny"
    assert "bad_signature" in _codes(result)


def test_unknown_signer_denied(trust_root, policy, clearance_valid):
    mutated = dict(clearance_valid)
    mutated["signer_key_id"] = "not-a-real-kid"
    # Re-sign so we isolate the kid check from signature failure.
    keys = load_fixture("dev_keys.json")
    mutated["signature"] = sign_clearance(
        mutated, private_from_raw_b64(keys["corp_private"])
    )
    result = admit_server(mutated, trust_root, policy)
    assert result.verdict == "deny"
    assert "unknown_signer" in _codes(result)


def test_issuer_mismatch_denied(trust_root, policy, clearance_valid):
    keys = load_fixture("dev_keys.json")
    mutated = dict(clearance_valid)
    mutated["issuer"] = "somebody-else"
    mutated["signature"] = sign_clearance(
        mutated, private_from_raw_b64(keys["corp_private"])
    )
    result = admit_server(mutated, trust_root, policy)
    assert result.verdict == "deny"
    assert "issuer_mismatch" in _codes(result)


def test_missing_signature_denied(trust_root, policy, clearance_valid):
    broken = {k: v for k, v in clearance_valid.items() if k != "signature"}
    result = admit_server(broken, trust_root, policy)
    assert result.verdict == "deny"
    assert "missing_field" in _codes(result)


def test_wrong_typ_denied(trust_root, policy, clearance_valid):
    keys = load_fixture("dev_keys.json")
    mutated = dict(clearance_valid)
    mutated["typ"] = "not-a-clearance"
    mutated["signature"] = sign_clearance(
        mutated, private_from_raw_b64(keys["corp_private"])
    )
    result = admit_server(mutated, trust_root, policy)
    assert result.verdict == "deny"
    assert "invalid_type" in _codes(result)


def test_policy_now_can_expire_otherwise_valid(trust_root, clearance_valid):
    future = Policy(
        expected_server_id="weather.internal",
        max_sensitivity="internal",
        now=datetime(2028, 6, 1, tzinfo=timezone.utc),
    )
    result = admit_server(clearance_valid, trust_root, future)
    assert result.verdict == "deny"
    assert "expired" in _codes(result)


def test_mapping_inputs_accepted():
    result = admit_server(
        load_fixture("clearance_valid.json"),
        load_fixture("trust_root.json"),
        load_fixture("policy.json"),
    )
    assert result.admitted is True


def test_admit_writes_audit(trust_root, policy, clearance_valid):
    audit = AuditLog()
    admit_server(clearance_valid, trust_root, policy, audit=audit)
    admit_server(load_fixture("clearance_forged.json"), trust_root, policy, audit=audit)
    assert [e["event"] for e in audit.entries] == ["mcp.connect.admit", "mcp.connect.deny"]
    assert audit.verify_chain() is True
