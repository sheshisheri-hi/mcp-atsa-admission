"""Append-only, hash-chained admission audit log."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from mcp_atsa_admission.canon import canonical_dumps, hex_digest

GENESIS_PREV = "0" * 64


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def chain_hash(prev: str, body: dict[str, Any]) -> str:
    """SHA-256 of canonical ``{...body, prev}``. ``hash`` itself is not covered."""
    covered = dict(body)
    covered["prev"] = prev
    return hex_digest(canonical_dumps(covered))


@dataclass
class AuditLog:
    """In-memory chain that can optionally persist JSONL to disk.

    Entries are append-only from this object's point of view: there is no
    rewrite API. Callers that need a file treat the JSONL as the record.
    """

    path: Path | None = None
    entries: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.path is not None:
            self.path = Path(self.path)
            if self.path.exists():
                self.entries = _read_jsonl(self.path)

    @property
    def head(self) -> str:
        if not self.entries:
            return GENESIS_PREV
        return str(self.entries[-1]["hash"])

    def append(
        self,
        event: str,
        *,
        verdict: str,
        server_id: str | None = None,
        tool_name: str | None = None,
        reason_codes: Iterable[str] = (),
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        prev = self.head
        body: dict[str, Any] = {
            "seq": len(self.entries) + 1,
            "ts": _utc_now(),
            "event": event,
            "verdict": verdict,
            "server_id": server_id,
            "tool_name": tool_name,
            "reason_codes": list(reason_codes),
        }
        if extra:
            body["extra"] = extra
        entry = dict(body)
        entry["prev"] = prev
        entry["hash"] = chain_hash(prev, body)
        self.entries.append(entry)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        return entry

    def verify_chain(self) -> bool:
        prev = GENESIS_PREV
        for entry in self.entries:
            body = {k: v for k, v in entry.items() if k not in ("hash", "prev")}
            expected = chain_hash(prev, body)
            if entry.get("prev") != prev or entry.get("hash") != expected:
                return False
            prev = str(entry["hash"])
        return True


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        rows.append(json.loads(line))
    return rows
