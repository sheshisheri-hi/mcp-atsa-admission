from __future__ import annotations

from mcp_atsa_admission.canon import canonical_dumps, canonical_hash
from mcp_atsa_admission.crypto import signing_body
from tests.conftest import load_fixture


def test_canonical_json_is_stable():
    left = {"b": 1, "a": {"z": True, "m": "x"}}
    right = {"a": {"m": "x", "z": True}, "b": 1}
    assert canonical_dumps(left) == canonical_dumps(right)
    assert canonical_hash(left) == canonical_hash(right)
    assert canonical_hash(left).startswith("sha256:")


def test_signature_covers_body_not_signature_field():
    clearance = load_fixture("clearance_valid.json")
    body = signing_body(clearance)
    assert "signature" not in body
    assert "server_id" in body
    # Hash of the published document includes the signature; signing body does not.
    assert canonical_hash(clearance) != canonical_hash(body)
