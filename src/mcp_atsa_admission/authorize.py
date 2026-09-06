"""Per-server tool allow-list. Admission is not a tool grant."""

from __future__ import annotations

from typing import Mapping

from mcp_atsa_admission.audit import AuditLog
from mcp_atsa_admission.models import AllowList, Reason, ToolDecision


def authorize_tool(
    server_id: str,
    tool_name: str,
    allow_list: AllowList | Mapping[str, object],
    *,
    audit: AuditLog | None = None,
) -> bool:
    """True only if ``tool_name`` is on the closed allow-list for ``server_id``.

    Call this *after* ``admit_server``. An admitted server still cannot
    dispatch a tool that is not listed.
    """
    return decide_tool(server_id, tool_name, allow_list, audit=audit).allowed


def decide_tool(
    server_id: str,
    tool_name: str,
    allow_list: AllowList | Mapping[str, object],
    *,
    audit: AuditLog | None = None,
) -> ToolDecision:
    listing = (
        allow_list if isinstance(allow_list, AllowList) else AllowList.from_mapping(allow_list)
    )
    reasons: list[Reason] = []
    if not server_id:
        reasons.append(
            Reason(code="missing_server_id", message="server_id is required.", field="server_id")
        )
    if not tool_name:
        reasons.append(
            Reason(code="missing_tool_name", message="tool_name is required.", field="tool_name")
        )

    if not reasons:
        if server_id not in listing.servers:
            reasons.append(
                Reason(
                    code="unknown_server",
                    message=f"No tool allow-list is configured for server '{server_id}'.",
                    field="server_id",
                )
            )
        elif not listing.allows(server_id, tool_name):
            allowed = ", ".join(sorted(listing.tools_for(server_id))) or "(empty)"
            reasons.append(
                Reason(
                    code="tool_not_allowlisted",
                    message=(
                        f"Tool '{tool_name}' is not on the allow-list for "
                        f"'{server_id}'. Refusing dispatch."
                    ),
                    field="tool_name",
                    detail=allowed,
                )
            )

    allowed = not reasons
    if allowed:
        reasons.append(
            Reason(
                code="tool_allowlisted",
                message=f"Tool '{tool_name}' is allow-listed for '{server_id}'.",
                field="tool_name",
            )
        )
    decision = ToolDecision(
        verdict="allow" if allowed else "deny",
        allowed=allowed,
        server_id=server_id,
        tool_name=tool_name,
        reasons=tuple(reasons),
    )
    if audit is not None:
        audit.append(
            "mcp.tool.allow" if allowed else "mcp.tool.deny",
            verdict=decision.verdict,
            server_id=server_id,
            tool_name=tool_name,
            reason_codes=[r.code for r in reasons],
        )
    return decision
