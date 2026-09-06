#!/usr/bin/env python3
"""Print-friendly mock: admit a signed server, deny forgeries, gate tools.

Run from the repo root:

    PYTHONPATH=src python examples/demo.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from mcp_atsa_admission import (  # noqa: E402
    AllowList,
    AuditLog,
    Policy,
    TrustRoot,
    admit_server,
    decide_tool,
)

FIXTURES = ROOT / "fixtures"
WIDTH = 72


def _box(title: str) -> None:
    print()
    print("=" * WIDTH)
    print(f" {title}")
    print("=" * WIDTH)


def _kv(label: str, value: str) -> None:
    print(f"  {label:<14} {value}")


def _load(name: str) -> dict:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _show_admit(title: str, name: str, root: TrustRoot, policy: Policy, audit: AuditLog) -> None:
    clearance = _load(name)
    result = admit_server(clearance, root, policy, audit=audit)
    _box(title)
    _kv("fixture", name)
    _kv("verdict", result.verdict.upper())
    _kv("server", result.server_id or "(unknown)")
    _kv("clearance", result.clearance_id or "(none)")
    _kv("hash", result.clearance_hash or "(none)")
    print("  reasons")
    for reason in result.reasons:
        loc = f" [{reason.field}]" if reason.field else ""
        print(f"    - {reason.code}{loc}: {reason.message}")


def _show_tool(title: str, server_id: str, tool: str, allow: AllowList, audit: AuditLog) -> None:
    decision = decide_tool(server_id, tool, allow, audit=audit)
    _box(title)
    _kv("server", server_id)
    _kv("tool", tool)
    _kv("verdict", decision.verdict.upper())
    print("  reasons")
    for reason in decision.reasons:
        loc = f" [{reason.field}]" if reason.field else ""
        print(f"    - {reason.code}{loc}: {reason.message}")


def main() -> int:
    print("MCP ATSA admission — check the server at the door")
    print("CPU only. No TPM. No Keycloak. No ACLE leases.")
    print()
    print("  OAuth        = badge (user may use this server)")
    print("  ATSA (here)  = door check (host may use this server as a tool provider)")
    print("  ACLE paper   = sticky note on each risky call (not implemented)")
    print()
    print("  connect --> [ admit_server ] --admit--> tools/list")
    print("                    |")
    print("                    +-- deny --> stop before dispatch")
    print("  call    --> [ authorize_tool ] --allow--> dispatch")
    print("                    |")
    print("                    +-- deny --> stop (allow-list miss)")

    root = TrustRoot.from_mapping(_load("trust_root.json"))
    policy = Policy.from_mapping(_load("policy.json"))
    allow = AllowList.from_mapping(_load("allow_list.json"))
    audit = AuditLog()

    _show_admit("1 / ADMIT — valid clearance + pinned trust root", "clearance_valid.json", root, policy, audit)
    _show_admit("2 / DENY — forged signature", "clearance_forged.json", root, policy, audit)
    _show_admit("3 / DENY — signed by the wrong key", "clearance_wrong_key.json", root, policy, audit)
    _show_admit("4 / DENY — expired clearance", "clearance_expired.json", root, policy, audit)
    _show_admit("5 / DENY — wrong server id", "clearance_wrong_server.json", root, policy, audit)
    _show_tool("6 / TOOL ALLOW — get_forecast is on the allow-list", "weather.internal", "get_forecast", allow, audit)
    _show_tool("7 / TOOL DENY — delete_account is not on the allow-list", "weather.internal", "delete_account", allow, audit)

    print()
    print("-" * WIDTH)
    print(f" Audit chain: {len(audit.entries)} events, verify={audit.verify_chain()}")
    for entry in audit.entries:
        print(f"  {entry['seq']:>2}  {entry['event']:<18} {entry['verdict']:<5}  {entry['hash'][:12]}…")
    print(" Demo done. Admit the signed server. Deny forgeries. Gate tools separately.")
    print(" CLI:  python -m mcp_atsa_admission fixtures/clearance_valid.json")
    print("       python -m mcp_atsa_admission tool weather.internal delete_account")
    print("-" * WIDTH)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
