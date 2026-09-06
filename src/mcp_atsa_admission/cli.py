"""CLI: ``python -m mcp_atsa_admission [admit] PATH`` or ``… tool SERVER TOOL``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence, TextIO

from mcp_atsa_admission.admit import admit_server
from mcp_atsa_admission.audit import AuditLog
from mcp_atsa_admission.authorize import decide_tool
from mcp_atsa_admission.models import AllowList, Policy, TrustRoot

_EXIT_OK = 0
_EXIT_USAGE = 1
_EXIT_DENY = 2

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_FIXTURES = _REPO_ROOT / "fixtures"


def main(argv: Sequence[str] | None = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    if tokens and tokens[0] in ("-h", "--help"):
        _build_parser().parse_args(tokens)
        return _EXIT_OK
    audit_path, tokens = _extract_option(tokens, "--audit")
    audit = AuditLog(path=Path(audit_path)) if audit_path else None
    command, rest = _split_command(tokens)
    if command == "tool":
        return _run_tool(rest, audit)
    return _run_admit(rest, audit)


def _split_command(tokens: list[str]) -> tuple[str, list[str]]:
    if tokens and tokens[0] == "tool":
        return "tool", tokens[1:]
    if tokens and tokens[0] == "admit":
        return "admit", tokens[1:]
    return "admit", tokens


def _extract_option(tokens: list[str], flag: str) -> tuple[str | None, list[str]]:
    out: list[str] = []
    value: str | None = None
    i = 0
    while i < len(tokens):
        token = tokens[i]
        if token == flag and i + 1 < len(tokens):
            value = tokens[i + 1]
            i += 2
            continue
        if token.startswith(flag + "="):
            value = token.split("=", 1)[1]
            i += 1
            continue
        out.append(token)
        i += 1
    return value, out


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-atsa-admission",
        description=(
            "Host-side ATSA door check: verify a signed clearance before "
            "any MCP tool dispatch, then authorize tools from a per-server "
            "allow-list."
        ),
    )
    parser.add_argument("--audit", metavar="FILE", help="Append-only JSONL audit log.")
    sub = parser.add_subparsers(dest="command")
    admit = sub.add_parser("admit", help="Verify a clearance assertion (default).")
    admit.add_argument("clearance", nargs="?", help="Clearance JSON path, or '-' for stdin.")
    admit.add_argument("--trust-root", help="Pinned trust-root JSON.")
    admit.add_argument("--policy", help="Host policy JSON.")
    admit.add_argument("--expected-server-id", help="Override expected server id.")
    tool = sub.add_parser("tool", help="Check a tool against the per-server allow-list.")
    tool.add_argument("server_id")
    tool.add_argument("tool_name")
    tool.add_argument("--allow-list", help="Per-server tool allow-list JSON.")
    return parser


def _run_admit(tokens: list[str], audit: AuditLog | None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-atsa-admission admit")
    parser.add_argument(
        "clearance",
        nargs="?",
        default=str(_DEFAULT_FIXTURES / "clearance_valid.json"),
        help="Path to clearance JSON, or '-' for stdin.",
    )
    parser.add_argument(
        "--trust-root",
        default=str(_DEFAULT_FIXTURES / "trust_root.json"),
    )
    parser.add_argument(
        "--policy",
        default=str(_DEFAULT_FIXTURES / "policy.json"),
    )
    parser.add_argument("--expected-server-id", default=None)
    try:
        args = parser.parse_args(tokens)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else _EXIT_USAGE

    try:
        clearance = _load_json(args.clearance)
        root = TrustRoot.from_mapping(_load_json(args.trust_root))
        policy_data = _load_json(args.policy)
        if args.expected_server_id:
            policy_data["expected_server_id"] = args.expected_server_id
        policy = Policy.from_mapping(policy_data)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        print(f"error: failed to load admission inputs: {exc}", file=sys.stderr)
        return _EXIT_USAGE

    result = admit_server(clearance, root, policy, audit=audit)
    _emit(result.to_dict(), sys.stdout)
    return _EXIT_OK if result.admitted else _EXIT_DENY


def _run_tool(tokens: list[str], audit: AuditLog | None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-atsa-admission tool")
    parser.add_argument("server_id")
    parser.add_argument("tool_name")
    parser.add_argument(
        "--allow-list",
        default=str(_DEFAULT_FIXTURES / "allow_list.json"),
    )
    try:
        args = parser.parse_args(tokens)
    except SystemExit as exc:
        return int(exc.code) if exc.code is not None else _EXIT_USAGE

    try:
        allow_list = AllowList.from_mapping(_load_json(args.allow_list))
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"error: failed to load allow-list: {exc}", file=sys.stderr)
        return _EXIT_USAGE
    decision = decide_tool(args.server_id, args.tool_name, allow_list, audit=audit)
    _emit(decision.to_dict(), sys.stdout)
    return _EXIT_OK if decision.allowed else _EXIT_DENY


def _load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def _emit(payload: dict[str, Any], stream: TextIO) -> None:
    json.dump(payload, stream, indent=2, ensure_ascii=False)
    stream.write("\n")


if __name__ == "__main__":
    raise SystemExit(main())
