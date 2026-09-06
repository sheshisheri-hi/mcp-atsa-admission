"""Connect-time admission: check the server at the door."""

from __future__ import annotations

from typing import Any, Mapping

from mcp_atsa_admission.audit import AuditLog
from mcp_atsa_admission.canon import canonical_hash
from mcp_atsa_admission.crypto import ALG_ED25519, verify_clearance_signature
from mcp_atsa_admission.models import (
    CLEARANCE_REQUIRED,
    AdmissionResult,
    Policy,
    Reason,
    TrustRoot,
    parse_utc,
)


def admit_server(
    clearance: Mapping[str, Any],
    trust_root: TrustRoot | Mapping[str, Any],
    policy: Policy | Mapping[str, Any] | None = None,
    *,
    audit: AuditLog | None = None,
) -> AdmissionResult:
    """Verify a published clearance against a pinned trust root.

    This is the host-side ATSA door check. It does **not** authorize
    individual tools — use ``authorize_tool`` after a successful admit.
    """
    root = trust_root if isinstance(trust_root, TrustRoot) else TrustRoot.from_mapping(trust_root)
    pol = policy if isinstance(policy, Policy) else Policy.from_mapping(policy)
    payload = dict(clearance)

    reasons: list[Reason] = []
    server_id = _as_str(payload.get("server_id"))
    clearance_id = _as_str(payload.get("id"))
    issuer = _as_str(payload.get("issuer"))
    sensitivity = _as_str(payload.get("sensitivity"))
    blob_hash = canonical_hash(payload)

    reasons.extend(_schema_reasons(payload))
    if not reasons:
        reasons.extend(_signature_reasons(payload, root))
    if not reasons:
        reasons.extend(_binding_reasons(payload, root, pol))

    verdict = "deny" if reasons else "admit"
    if verdict == "admit":
        reasons.append(
            Reason(
                code="clearance_ok",
                message=(
                    f"Clearance '{clearance_id}' for server '{server_id}' "
                    f"verified against pinned trust root '{root.id}'."
                ),
            )
        )

    result = AdmissionResult(
        verdict=verdict,
        reasons=tuple(reasons),
        server_id=server_id,
        clearance_id=clearance_id,
        clearance_hash=blob_hash,
        issuer=issuer,
        sensitivity=sensitivity,
    )
    if audit is not None:
        audit.append(
            "mcp.connect.admit" if result.admitted else "mcp.connect.deny",
            verdict=result.verdict,
            server_id=server_id,
            reason_codes=[r.code for r in reasons],
            extra={"clearance_id": clearance_id, "clearance_hash": blob_hash},
        )
    return result


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    return str(value)


def _schema_reasons(payload: dict[str, Any]) -> list[Reason]:
    reasons: list[Reason] = []
    if not payload:
        return [Reason(code="malformed_clearance", message="Clearance is empty.")]
    for name in CLEARANCE_REQUIRED:
        if name not in payload or payload[name] in (None, ""):
            reasons.append(
                Reason(
                    code="missing_field",
                    message=f"Clearance is missing required field '{name}'.",
                    field=name,
                )
            )
    if reasons:
        return reasons
    if payload.get("typ") != "mcp-clearance":
        reasons.append(
            Reason(
                code="invalid_type",
                message="Clearance typ must be 'mcp-clearance'.",
                field="typ",
                detail=str(payload.get("typ")),
            )
        )
    if payload.get("v") != 1:
        reasons.append(
            Reason(
                code="unsupported_version",
                message="Clearance v must be 1.",
                field="v",
                detail=str(payload.get("v")),
            )
        )
    return reasons


def _signature_reasons(payload: dict[str, Any], root: TrustRoot) -> list[Reason]:
    kid = str(payload.get("signer_key_id") or "")
    key = root.key(kid)
    if key is None:
        return [
            Reason(
                code="unknown_signer",
                message=f"signer_key_id '{kid}' is not in the pinned trust root.",
                field="signer_key_id",
                detail=root.id,
            )
        ]
    if key.alg != ALG_ED25519:
        return [
            Reason(
                code="unsupported_algorithm",
                message=f"Trust root key '{kid}' uses unsupported alg '{key.alg}'.",
                field="signer_key_id",
                detail=key.alg,
            )
        ]
    if not verify_clearance_signature(payload, key.public_key):
        return [
            Reason(
                code="bad_signature",
                message=(
                    "Clearance signature did not verify under the pinned "
                    f"trust-root key '{kid}'."
                ),
                field="signature",
            )
        ]
    return []


def _binding_reasons(
    payload: dict[str, Any],
    root: TrustRoot,
    policy: Policy,
) -> list[Reason]:
    reasons: list[Reason] = []
    issuer = str(payload.get("issuer") or "")
    if issuer != root.id:
        reasons.append(
            Reason(
                code="issuer_mismatch",
                message=f"Clearance issuer '{issuer}' does not match trust root '{root.id}'.",
                field="issuer",
                detail=root.id,
            )
        )

    server_id = str(payload.get("server_id") or "")
    if policy.expected_server_id and server_id != policy.expected_server_id:
        reasons.append(
            Reason(
                code="server_id_mismatch",
                message=(
                    f"Clearance server_id '{server_id}' is not the expected "
                    f"'{policy.expected_server_id}'."
                ),
                field="server_id",
                detail=policy.expected_server_id,
            )
        )

    sensitivity = str(payload.get("sensitivity") or "")
    if not policy.sensitivity_allowed(sensitivity):
        reasons.append(
            Reason(
                code="sensitivity_denied",
                message=(
                    f"Claimed sensitivity '{sensitivity}' exceeds host max "
                    f"'{policy.max_sensitivity}'."
                ),
                field="sensitivity",
                detail=policy.max_sensitivity,
            )
        )

    now = policy.clock()
    try:
        not_before = parse_utc(str(payload["not_before"]))
        not_after = parse_utc(str(payload["not_after"]))
    except (KeyError, TypeError, ValueError) as exc:
        reasons.append(
            Reason(
                code="invalid_time",
                message="Clearance not_before / not_after is not valid ISO-8601.",
                detail=str(exc),
            )
        )
        return reasons

    if not_after < not_before:
        reasons.append(
            Reason(
                code="invalid_time",
                message="Clearance not_after is before not_before.",
                field="not_after",
            )
        )
    if now < not_before:
        reasons.append(
            Reason(
                code="not_yet_valid",
                message=f"Clearance is not valid until {payload['not_before']}.",
                field="not_before",
            )
        )
    if now > not_after:
        reasons.append(
            Reason(
                code="expired",
                message=f"Clearance expired at {payload['not_after']}.",
                field="not_after",
            )
        )
    return reasons
