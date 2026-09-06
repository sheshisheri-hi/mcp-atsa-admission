"""Clearance, trust root, policy, and admission result types."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Mapping

Verdict = Literal["admit", "deny"]
ToolVerdict = Literal["allow", "deny"]

SENSITIVITY_RANK = {
    "public": 0,
    "internal": 1,
    "confidential": 2,
    "restricted": 3,
}

CLEARANCE_REQUIRED = (
    "typ",
    "v",
    "id",
    "server_id",
    "issuer",
    "issued_at",
    "not_before",
    "not_after",
    "sensitivity",
    "signer_key_id",
    "signature",
)


def parse_utc(value: str) -> datetime:
    """Parse an ISO-8601 timestamp. ``Z`` and offsets are accepted."""
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


@dataclass(frozen=True)
class TrustKey:
    kid: str
    alg: str
    public_key: str

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> TrustKey:
        return cls(
            kid=str(data["kid"]),
            alg=str(data.get("alg", "Ed25519")),
            public_key=str(data["public_key"]),
        )


@dataclass(frozen=True)
class TrustRoot:
    """Pinned host-side trust root. Not fetched from the server."""

    id: str
    keys: tuple[TrustKey, ...]

    def key(self, kid: str) -> TrustKey | None:
        for item in self.keys:
            if item.kid == kid:
                return item
        return None

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any]) -> TrustRoot:
        keys = tuple(TrustKey.from_mapping(k) for k in data.get("keys") or ())
        return cls(id=str(data["id"]), keys=keys)


@dataclass(frozen=True)
class Policy:
    """Host admission policy. Admitting a server is not a tool grant."""

    expected_server_id: str | None = None
    max_sensitivity: str = "internal"
    now: datetime | None = None

    def clock(self) -> datetime:
        if self.now is not None:
            return self.now if self.now.tzinfo else self.now.replace(tzinfo=timezone.utc)
        return datetime.now(timezone.utc)

    def sensitivity_allowed(self, claimed: str) -> bool:
        claim = SENSITIVITY_RANK.get(claimed)
        limit = SENSITIVITY_RANK.get(self.max_sensitivity)
        if claim is None or limit is None:
            return False
        return claim <= limit

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> Policy:
        if not data:
            return cls()
        kwargs: dict[str, Any] = {}
        if "expected_server_id" in data:
            value = data["expected_server_id"]
            kwargs["expected_server_id"] = None if value is None else str(value)
        if "max_sensitivity" in data:
            kwargs["max_sensitivity"] = str(data["max_sensitivity"])
        if data.get("now"):
            kwargs["now"] = parse_utc(str(data["now"]))
        return cls(**kwargs)


@dataclass(frozen=True)
class AllowList:
    """Closed per-server tool allow-list. Unknown server or tool is deny."""

    servers: dict[str, frozenset[str]] = field(default_factory=dict)

    def tools_for(self, server_id: str) -> frozenset[str]:
        return self.servers.get(server_id, frozenset())

    def allows(self, server_id: str, tool_name: str) -> bool:
        if not server_id or not tool_name:
            return False
        return tool_name in self.tools_for(server_id)

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any] | None) -> AllowList:
        if not data:
            return cls()
        raw = data.get("servers", data)
        servers: dict[str, frozenset[str]] = {}
        if isinstance(raw, Mapping):
            for server_id, tools in raw.items():
                servers[str(server_id)] = frozenset(str(t) for t in (tools or ()))
        return cls(servers=servers)


@dataclass(frozen=True)
class Reason:
    """One explainable finding. ``field`` is a dotted path when possible."""

    code: str
    message: str
    field: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass(frozen=True)
class AdmissionResult:
    """Connect-time verdict. ``admit`` is not a blanket tool grant."""

    verdict: Verdict
    reasons: tuple[Reason, ...]
    server_id: str | None = None
    clearance_id: str | None = None
    clearance_hash: str | None = None
    issuer: str | None = None
    sensitivity: str | None = None

    @property
    def admitted(self) -> bool:
        return self.verdict == "admit"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reasons": [r.to_dict() for r in self.reasons],
            "server_id": self.server_id,
            "clearance_id": self.clearance_id,
            "clearance_hash": self.clearance_hash,
            "issuer": self.issuer,
            "sensitivity": self.sensitivity,
        }


@dataclass(frozen=True)
class ToolDecision:
    """Per-dispatch allow-list check. Separate from connect-time admission."""

    verdict: ToolVerdict
    allowed: bool
    server_id: str
    tool_name: str
    reasons: tuple[Reason, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "allowed": self.allowed,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "reasons": [r.to_dict() for r in self.reasons],
        }
