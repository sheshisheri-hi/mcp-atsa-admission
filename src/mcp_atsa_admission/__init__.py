"""Thin ATSA host-side admission gate — check the MCP tool server at the door.

Inspired by draft SEP-2809 (Attested Tool-Server Admission). This is not a
full SEP port and does not implement ACLE leases, Keycloak, or a vTPM.
"""

from mcp_atsa_admission.admit import admit_server
from mcp_atsa_admission.audit import AuditLog
from mcp_atsa_admission.authorize import authorize_tool, decide_tool
from mcp_atsa_admission.canon import canonical_hash
from mcp_atsa_admission.models import (
    AdmissionResult,
    AllowList,
    Policy,
    Reason,
    ToolDecision,
    TrustRoot,
)

__all__ = [
    "AdmissionResult",
    "AllowList",
    "AuditLog",
    "Policy",
    "Reason",
    "ToolDecision",
    "TrustRoot",
    "admit_server",
    "authorize_tool",
    "canonical_hash",
    "decide_tool",
]

__version__ = "0.1.0"
