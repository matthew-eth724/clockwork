"""Conditional Kill Memory.

A kill is *negative precedent*, never a permanent suppression. It records the
mechanism, the blocking claim, the evidence that supported the blocker, the
repository and commit range it applied to, the conditions that would invalidate
the blocker, an author and an independent verifier.

Any new investigation that matches a kill must supply evidence addressing one of
the recorded invalidation conditions. Absent that, the lane is *blocked with a
pointer*, not silently dropped — and the block itself is recorded as an edge.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class KillMemoryViolation(Exception):
    pass


@dataclass
class KillCheck:
    precedent_kill_ids: list[str] = field(default_factory=list)
    must_evidence: list[str] = field(default_factory=list)
    satisfied_by: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return bool(self.precedent_kill_ids) and not self.satisfied_by

    def to_dict(self) -> dict:
        return {"blocked": self.blocked,
                "precedent_kill_ids": self.precedent_kill_ids,
                "must_evidence": self.must_evidence,
                "satisfied_by": self.satisfied_by}


def commit_overlaps(kill_range: str | None, branch_range: str | None) -> bool:
    """A kill applies only to commits it actually covered.

    Ranges are ``a..b`` or a single sha. An empty kill range means the blocker
    was environmental and applies to any commit.
    """
    if not kill_range:
        return True
    if not branch_range:
        return False
    if kill_range == branch_range:
        return True
    a = kill_range.replace("..", "..").split("..")
    b = branch_range.split("..")
    if len(a) == 2 and len(b) == 2:
        return a[0] == b[0]
    return kill_range.startswith(branch_range) or branch_range.startswith(kill_range)


def check_against_kills(kills: dict[str, dict], *, fingerprint: str,
                        repo_id: str | None, commit_range: str | None,
                        offered_evidence: list[str]) -> KillCheck:
    """``offered_evidence`` are evidence ids the new lane proposes to cover the
    recorded invalidation conditions. The caller is responsible for those
    evidence ids actually existing and being unverified-by-self."""
    out = KillCheck()
    for kill in kills.values():
        if kill.get("repo_id") and repo_id and kill["repo_id"] != repo_id:
            continue
        if kill.get("fingerprint") and kill["fingerprint"] != fingerprint:
            continue
        if not commit_overlaps(kill.get("commit_range"), commit_range):
            continue
        if kill.get("invalidated_by"):
            continue
        out.precedent_kill_ids.append(kill["kill_id"])
        out.must_evidence.extend(kill.get("invalidation_conditions") or [])
    if out.precedent_kill_ids:
        usable = set(offered_evidence)
        out.satisfied_by = sorted(usable & set(out.must_evidence))
    return out


def validate_kill_record(rec: dict[str, Any]) -> None:
    required = ("kill_id", "suspected_mechanism", "blocking_claim_id",
                "evidence_ids", "invalidation_conditions", "author_id",
                "verifier_id")
    missing = [k for k in required if not rec.get(k)]
    if missing:
        raise KillMemoryViolation(f"kill record missing fields: {missing}")
    if rec["author_id"] == rec["verifier_id"]:
        raise KillMemoryViolation(
            "kill record must be verified by someone other than its author")
    if not rec["evidence_ids"]:
        raise KillMemoryViolation("kill must carry supporting evidence ids")
    if not rec["invalidation_conditions"]:
        raise KillMemoryViolation(
            "kill must declare the conditions that would invalidate its blocker")
