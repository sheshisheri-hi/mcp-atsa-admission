#!/usr/bin/env python3
"""Regenerate signed clearance fixtures. Sample keys only — not secrets."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_atsa_admission.crypto import (  # noqa: E402
    b64url_encode,
    private_from_raw_b64,
    sign_clearance,
)
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

# Deterministic sample seeds (32 raw bytes, base64url). Safe to commit.
CORP_PRIVATE_B64 = "i8MyLU7jKM0O0lZlfMcihUkgcj6McTcNzOwGkk01kDA"
EVIL_PRIVATE_B64 = "oa8HWobBK71QdLj3ij4ZnVu7DtwSSikIoUKT3pqWshk"


def _public_b64(private_b64: str) -> str:
    private = private_from_raw_b64(private_b64)
    raw = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return b64url_encode(raw)


def _write(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def _signed(body: dict, private_b64: str) -> dict:
    private = private_from_raw_b64(private_b64)
    clearance = dict(body)
    clearance["signature"] = sign_clearance(clearance, private)
    return clearance


def main() -> int:
    fixtures = ROOT / "fixtures"
    fixtures.mkdir(exist_ok=True)

    corp_pub = _public_b64(CORP_PRIVATE_B64)
    evil_pub = _public_b64(EVIL_PRIVATE_B64)

    trust_root = {
        "id": "corp-trust-root",
        "keys": [
            {
                "kid": "corp-trust-root-ed25519-1",
                "alg": "Ed25519",
                "public_key": corp_pub,
            }
        ],
    }
    other_root = {
        "id": "other-trust-root",
        "keys": [
            {
                "kid": "other-trust-root-ed25519-1",
                "alg": "Ed25519",
                "public_key": evil_pub,
            }
        ],
    }

    valid_body = {
        "typ": "mcp-clearance",
        "v": 1,
        "id": "clr-weather-2026",
        "server_id": "weather.internal",
        "issuer": "corp-trust-root",
        "issued_at": "2026-01-15T00:00:00Z",
        "not_before": "2026-01-15T00:00:00Z",
        "not_after": "2027-12-31T23:59:59Z",
        "sensitivity": "internal",
        "well_known": "https://weather.internal/.well-known/mcp-clearance",
        "signer_key_id": "corp-trust-root-ed25519-1",
    }
    valid = _signed(valid_body, CORP_PRIVATE_B64)

    forged = dict(valid)
    forged["signature"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    wrong_key = dict(valid_body)
    wrong_key["signature"] = sign_clearance(wrong_key, private_from_raw_b64(EVIL_PRIVATE_B64))

    expired = _signed(
        {
            **valid_body,
            "id": "clr-weather-expired",
            "issued_at": "2024-01-01T00:00:00Z",
            "not_before": "2024-01-01T00:00:00Z",
            "not_after": "2025-01-01T00:00:00Z",
        },
        CORP_PRIVATE_B64,
    )

    wrong_server = _signed(
        {
            **valid_body,
            "id": "clr-evil-2026",
            "server_id": "evil.example",
            "well_known": "https://evil.example/.well-known/mcp-clearance",
        },
        CORP_PRIVATE_B64,
    )

    not_yet = _signed(
        {
            **valid_body,
            "id": "clr-weather-future",
            "not_before": "2028-01-01T00:00:00Z",
            "not_after": "2028-12-31T23:59:59Z",
        },
        CORP_PRIVATE_B64,
    )

    confidential = _signed(
        {
            **valid_body,
            "id": "clr-weather-confidential",
            "sensitivity": "confidential",
        },
        CORP_PRIVATE_B64,
    )

    policy = {
        "expected_server_id": "weather.internal",
        "max_sensitivity": "internal",
    }
    allow_list = {
        "servers": {
            "weather.internal": ["get_forecast", "get_alerts"],
        }
    }
    keys = {
        "_comment": "Sample keys for regenerating fixtures. Not production secrets.",
        "corp_private": CORP_PRIVATE_B64,
        "corp_public": corp_pub,
        "evil_private": EVIL_PRIVATE_B64,
        "evil_public": evil_pub,
    }

    _write(fixtures / "trust_root.json", trust_root)
    _write(fixtures / "trust_root_other.json", other_root)
    _write(fixtures / "clearance_valid.json", valid)
    _write(fixtures / "clearance_forged.json", forged)
    _write(fixtures / "clearance_wrong_key.json", wrong_key)
    _write(fixtures / "clearance_expired.json", expired)
    _write(fixtures / "clearance_wrong_server.json", wrong_server)
    _write(fixtures / "clearance_not_yet_valid.json", not_yet)
    _write(fixtures / "clearance_confidential.json", confidential)
    _write(fixtures / "policy.json", policy)
    _write(fixtures / "allow_list.json", allow_list)
    _write(fixtures / "dev_keys.json", keys)
    print(f"Wrote fixtures under {fixtures}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
