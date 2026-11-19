"""Fact model returned by the projector.

The projector turns the append-only event log into an immutable *fact set*.
Agents, gates, context cutting and report generation all read facts — never the
mutable projection tables — so the same event log always yields the same
decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, eq=False)
class FactNode:
    node_id: str
    kind: str
    label: str
    seq: int
    branch_id: str | None = None
    orbit: str = "system"
    status: str = "active"
    attrs: dict[str, Any] = field(default_factory=dict)
    commit_sha: str | None = None
    source_ref: str | None = None
    content_hash: str | None = None
    sealed_seq: int | None = None

    def has(self, key: str) -> bool:
        return bool(self.attrs.get(key))

    def get(self, key: str, default=None):
        return self.attrs.get(key, default)


@dataclass(frozen=True)
class FactEdge:
    src_id: str
    rel: str
    dst_id: str
    seq: int
    produced_by: str = "system"
    attrs: dict[str, Any] = field(default_factory=dict)
    retired_seq: int | None = None


@dataclass
class Facts:
    case_id: str
    upto_seq: int
    nodes: dict[str, FactNode] = field(default_factory=dict)
    edges: list[FactEdge] = field(default_factory=list)
    seals: dict[str, dict] = field(default_factory=dict)
    merges: list[dict] = field(default_factory=list)
    kills: dict[str, dict] = field(default_factory=dict)
    precedents: dict[str, dict] = field(default_factory=dict)
    branch_state: dict[str, dict] = field(default_factory=dict)
    report_sections: list[dict] = field(default_factory=list)
    gate_decisions: dict[tuple[str, str], dict] = field(default_factory=dict)
    human_decisions: list[dict] = field(default_factory=list)
    authority: dict[str, dict] = field(default_factory=dict)

    # ------------------------------------------------------------- queries
    def of_kind(self, kind: str) -> list[FactNode]:
        return [n for n in self.nodes.values() if n.kind == kind]

    def branch_nodes(self, branch_id: str, kind: str | None = None) -> list[FactNode]:
        return [n for n in self.nodes.values()
                if n.branch_id == branch_id and (kind is None or n.kind == kind)]

    def live_edges(self, rel: str | None = None) -> list[FactEdge]:
        return [e for e in self.edges
                if e.retired_seq is None and (rel is None or e.rel == rel)]

    def edges_from(self, node_id: str, rel: str | None = None) -> list[FactEdge]:
        return [e for e in self.live_edges(rel) if e.src_id == node_id]

    def edges_to(self, node_id: str, rel: str | None = None) -> list[FactEdge]:
        return [e for e in self.live_edges(rel) if e.dst_id == node_id]

    def neighbours(self, node_id: str, rel=None, direction: str = "both") -> set[str]:
        out: set[str] = set()
        for e in self.live_edges(rel):
            if e.src_id == node_id and direction in ("both", "out"):
                out.add(e.dst_id)
            if e.dst_id == node_id and direction in ("both", "in"):
                out.add(e.src_id)
        return out

    def gate_state(self, branch_id: str, gate_id: str) -> str:
        row = self.gate_decisions.get((branch_id, gate_id))
        return row["state"] if row else "PENDING"

    def node(self, node_id: str) -> FactNode | None:
        return self.nodes.get(node_id)

    def exists(self, node_id: str) -> bool:
        return node_id in self.nodes
