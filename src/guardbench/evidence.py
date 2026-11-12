"""Append-only, hash-chained decision log.

Each record stores the SHA-256 hash of the record before it. Changing or
removing any record breaks every hash after it, so tampering is detectable
by anyone who holds the file and a trusted copy of the last hash.

Maps to MITRE ATLAS mitigation AML.M0024 (AI Telemetry Logging).
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(body: dict) -> str:
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class EvidenceLog:
    """Writes one JSON record per guardrail decision."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = GENESIS
        if self.path.exists():
            lines = self.path.read_text(encoding="utf-8").splitlines()
            if lines:
                self._prev = json.loads(lines[-1])["hash"]

    @property
    def head(self) -> str:
        """Hash of the latest record. Anchor this somewhere the log's owner cannot edit."""
        return self._prev

    def write(
        self,
        *,
        principal: str,
        agent: str,
        stage: str,
        decision: str,
        reason: str = "",
        parent_agent: str | None = None,
        requested_scope: str | None = None,
        granted_scope: str | None = None,
        policy_version: str = "unversioned",
        **extra: str,
    ) -> dict:
        body = {
            "prev": self._prev,
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "principal": principal,
            "agent": agent,
            "parent_agent": parent_agent,
            "stage": stage,
            "decision": decision,
            "reason": reason,
            "requested_scope": requested_scope,
            "granted_scope": granted_scope,
            "policy_version": policy_version,
            **extra,
        }
        record = {**body, "hash": _digest(body)}
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        self._prev = record["hash"]
        return record


def verify_chain(path: str | Path, expected_head: str | None = None) -> tuple[bool, str]:
    """Check every link in the chain. Returns (ok, message)."""
    prev = GENESIS
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    for number, line in enumerate(lines, start=1):
        record = json.loads(line)
        claimed = record.pop("hash", None)
        if record.get("prev") != prev:
            return False, f"record {number}: does not link to the record before it"
        if _digest(record) != claimed:
            return False, f"record {number}: content does not match its hash"
        prev = claimed
    if expected_head is not None and prev != expected_head:
        return False, "chain is intact but its head does not match the expected hash (records removed or replaced)"
    return True, f"{len(lines)} records verified"
