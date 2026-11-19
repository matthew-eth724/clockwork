"""Role-specific context packets.

A packet is the *minimum connected subgraph* that lets one agent do one task:
seed it with the task's anchor nodes, run a bounded multi-source BFS over the
typed graph, and stop. Full transcripts never enter a packet.

Summaries may be inserted as clearly-marked disposable cache text, and are
excluded from the evidence-bearing part of the packet.
"""
from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from .facts import Facts

# Role -> (anchor selection, allowed node kinds, allowed relations, depth, caps)
ROLES: dict[str, dict[str, Any]] = {
    "attack_orbit": {
        "anchors": ["branch", "claim", "experiment"],
        "kinds": {"branch", "claim", "assumption", "experiment", "evidence",
                  "commit", "artifact", "scope_snapshot", "impact", "fix"},
        "rels": {"SUPPORTS", "CONTRADICTS", "DEPENDS_ON", "TESTS",
                 "GENERATED_BY", "APPLIES_TO_COMMIT", "RULES_OUT"},
        "depth": 3, "max_nodes": 40,
        "forbidden_orbits": {"defense", "history", "impact"},  # blind
    },
    "defense_orbit": {
        "anchors": ["branch", "claim", "control"],
        "kinds": {"branch", "claim", "assumption", "experiment", "evidence",
                  "control", "commit", "artifact"},
        "rels": {"SUPPORTS", "CONTRADICTS", "DEPENDS_ON", "TESTS", "RULES_OUT",
                 "GENERATED_BY", "BLOCKED_BY", "APPLIES_TO_COMMIT"},
        "depth": 3, "max_nodes": 40,
        "forbidden_orbits": {"attack", "history", "impact"},
    },
    "history_orbit": {
        "anchors": ["branch", "fingerprint"],
        "kinds": {"branch", "claim", "evidence", "commit", "fix", "precedent",
                  "fingerprint", "artifact"},
        "rels": {"DUPLICATE_OF", "FIXED_BY", "ABSTRACTS_TO", "APPLIES_TO_COMMIT",
                 "SUPPORTS", "DEPENDS_ON"},
        "depth": 4, "max_nodes": 60,
        "forbidden_orbits": {"attack", "defense", "impact"},
        "include_precedent": True,
    },
    "impact_orbit": {
        "anchors": ["branch", "claim", "impact"],
        "kinds": {"branch", "claim", "evidence", "experiment", "impact",
                  "artifact", "commit", "scope_snapshot"},
        "rels": {"SUPPORTS", "DEPENDS_ON", "TESTS", "GENERATED_BY"},
        "depth": 3, "max_nodes": 40,
        "forbidden_orbits": {"attack", "defense", "history"},
    },
    "gate_verifier": {
        "anchors": ["branch"],
        "kinds": {"branch", "claim", "evidence", "experiment", "control",
                  "artifact", "impact", "commit", "scope_snapshot", "fix",
                  "precedent"},
        "rels": {"SUPPORTS", "CONTRADICTS", "TESTS", "GENERATED_BY",
                 "VERIFIED_BY", "DEPENDS_ON", "RULES_OUT", "APPLIES_TO_COMMIT"},
        "depth": 2, "max_nodes": 80,
    },
    "qc_reviewer": {
        "anchors": ["branch", "claim", "report_section"],
        "kinds": {"branch", "claim", "evidence", "experiment", "control",
                  "artifact", "impact", "fix", "precedent", "commit",
                  "report_section"},
        "rels": {"SUPPORTS", "CONTRADICTS", "TESTS", "GENERATED_BY",
                 "VERIFIED_BY", "INCLUDED_IN", "DEPENDS_ON", "APPLIES_TO_COMMIT"},
        "depth": 3, "max_nodes": 120,
    },
}


@dataclass
class ContextPacket:
    packet_id: str
    case_id: str
    agent_id: str
    role: str
    node_ids: list[str] = field(default_factory=list)
    edges: list[dict] = field(default_factory=list)
    nodes: list[dict] = field(default_factory=list)
    task: dict = field(default_factory=dict)
    withheld: dict = field(default_factory=dict)
    disposable_summary: str | None = None
    stats: dict = field(default_factory=dict)

    @property
    def visible_nodes(self) -> list[dict]:
        return [n for n in self.nodes if n.get("sealed_seq") is None
                or self.role in n.get("orbit", "").split("+")]

    def to_dict(self) -> dict:
        return {
            "packet_id": self.packet_id, "case_id": self.case_id,
            "agent_id": self.agent_id, "role": self.role,
            "task": self.task,
            "nodes": self.nodes, "edges": self.edges,
            "withheld": self.withheld,
            "disposable_summary": self.disposable_summary,
            "stats": self.stats,
            "canonical": False,
        }


def _node_payload(n) -> dict:
    return {
        "id": n.node_id, "kind": n.kind, "label": n.label,
        "orbit": n.orbit, "sequence": n.seq,
        "attrs": n.attrs, "commit": n.commit_sha, "source_ref": n.source_ref,
    }


def cut_packet(facts: Facts, *, role: str, agent_id: str, branch_id: str,
               task: dict | None = None,
               extra_anchors: Iterable[str] = (),
               summary_cache: str | None = None,
               stage: str | None = None) -> ContextPacket:
    if role not in ROLES:
        raise ValueError(f"unknown role {role!r}")
    spec = ROLES[role]
    task = task or {}
    allowed_kinds: set[str] = spec["kinds"]
    allowed_rels: set[str] = spec["rels"]
    forbidden_orbits: set[str] = spec.get("forbidden_orbits", set())

    # ---- anchors ----------------------------------------------------------
    withheld_by_orbit: dict[str, int] = {}
    anchors: list[str] = []
    for kind in spec["anchors"]:
        for n in facts.branch_nodes(branch_id, kind):
            if n.node_id == branch_id:
                continue          # the lane itself is always a structural anchor
            if _is_blinded_for(facts, role, n):
                withheld_by_orbit[n.orbit] = withheld_by_orbit.get(n.orbit, 0) + 1
                continue
            anchors.append(n.node_id)
    for extra in extra_anchors:
        if extra in facts.nodes:
            anchors.append(extra)
    # the branch node is a shared structural anchor: what is blinded is the
    # *evidence and claims* an orbit produced, not the existence of the lane
    for n in facts.of_kind("branch"):
        if n.node_id == branch_id:
            anchors.append(n.node_id)
    anchors = list(dict.fromkeys(anchors))

    kept: list[str] = []
    seen: set[str] = set()
    q: deque[tuple[str, int]] = deque((a, 0) for a in anchors)
    kept.extend(anchors)
    seen.update(anchors)

    while q and len(kept) < spec["max_nodes"]:
        node_id, depth = q.popleft()
        node = facts.node(node_id)
        if node is None:
            continue
        if depth >= spec["depth"]:
            continue
        neighbours: list[str] = []
        for e in facts.edges:
            if e.retired_seq is not None or e.rel not in allowed_rels:
                continue
            if e.src_id == node_id:
                neighbours.append(e.dst_id)
            elif e.dst_id == node_id:
                neighbours.append(e.src_id)
        for nid in neighbours:
            if nid in seen:
                continue
            n2 = facts.node(nid)
            if n2 is None:
                continue
            if n2.kind not in allowed_kinds:
                continue
            # blind orbit: results of other orbits are structurally absent
            if _is_blinded_for(facts, role, n2):
                withheld_by_orbit[n2.orbit] = withheld_by_orbit.get(n2.orbit, 0) + 1
                continue
            seen.add(nid)
            kept.append(nid)
            q.append((nid, depth + 1))
            if len(kept) >= spec["max_nodes"]:
                break

    nodes = [facts.node(i) for i in kept if facts.node(i)]
    edges = [
        {"src": e.src_id, "rel": e.rel, "dst": e.dst_id}
        for e in facts.live_edges()
        if e.rel in allowed_rels and e.src_id in seen and e.dst_id in seen
    ]

    packet = ContextPacket(
        packet_id="pkt:" + hashlib.sha256(
            json.dumps([role, agent_id, branch_id, kept], sort_keys=True)
            .encode()).hexdigest()[:20],
        case_id=facts.case_id, agent_id=agent_id, role=role,
        node_ids=kept,
        nodes=[_node_payload(n) for n in nodes],
        edges=edges,
        task=task,
        withheld={"blinded_orbit_nodes": withheld_by_orbit,
                  "note": "Other orbit results are structurally absent until the "
                          "orbit merge event, not merely redacted."},
        disposable_summary=summary_cache,
        stats={"nodes": len(kept), "edges": len(edges),
               "full_case_nodes": len(facts.nodes),
               "fraction_of_case": round(len(kept) / max(1, len(facts.nodes)), 3),
               "depth": spec["depth"]},
    )
    return packet


def _seal_seq(facts: Facts, role: str) -> int:
    """Sequence at which the role's own orbit sealed, else 0."""
    if role in facts.seals:
        return facts.seals[role]["sealed_seq"]
    return 0


def orbit_stage(facts: Facts, orbit: str) -> str:
    """``live``    — the orbit is speculative: it is invisible to other orbits.
    ``sealed``  — the orbit has declared its output; still blind to others.
    ``public``  — the orbit was consumed by a merge, or its lane was killed:
    it is negative precedent, not live speculation, and other orbits may
    reason about it."""
    if not facts.seals.get(orbit):
        return "live"
    merged: set[str] = set()
    for m in facts.merges:
        merged.update(m.get("orbits") or str(m.get("orbit", "")).split("+"))
    if orbit in merged:
        return "public"
    killed_orbits = {facts.node(k.get("branch_id") or "").orbit
                     for k in facts.kills.values()
                     if facts.node(k.get("branch_id") or "")}
    return "public" if orbit in killed_orbits else "sealed"


def _is_blinded_for(facts: Facts, role: str, node) -> bool:
    """A node produced by an orbit is invisible to another orbit until both have
    sealed and the merge event has been recorded."""
    if node.orbit in ("system", role):
        return False
    return orbit_stage(facts, node.orbit) != "public"
