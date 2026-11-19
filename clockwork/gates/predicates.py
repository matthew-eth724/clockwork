"""Machine-readable gate transition predicates.

A gate is not a checklist item: it is a small program over the epistemic graph.
Each predicate is a JSON document (``{"all": [...]}/{"any": [...]}/leaf``) that
the runtime evaluates against a *GateContext* snapshot of the case graph.

Leaf forms (all of them resolve to a boolean plus a human-readable reason):

    {"previous_gate_passed": "<gate_id>"}
    {"has_node": "claim"|"evidence"|"experiment"|..., "branch": true}
    {"min_nodes": {"kind": "evidence", "n": 2}}
    {"edge_exists": {"rel": "TESTS", "src_kind": "experiment", "dst_kind": "claim"}}
    {"edge_from": {"rel": "SUPPORTS", "node": "<id>"}, "count": 1}
    {"evidence_kind": {"kind": "control", "n": 1}}
    {"experiment_outcome": {"outcome": "pass", "n": 1}}
    {"control_result": {"result": "held", "n": 1}}
    {"proof_binding_complete": true}
    {"artifact_hashed": {"n": 1}}
    {"gate_passed": "<gate_id>"}
    {"independent_verifier": true}
    {"independent_verifier_role": "human"}
    {"verifier_not_author": true}
    {"no_open_contradictions": true}
    {"contradictions_resolved": true}
    {"assumptions_declared": true}
    {"orbit_sealed": "attack"|"defense"|"history"|"impact"}
    {"orbits_merged": true}
    {"novelty_fingerprint": true}
    {"duplicate_checked": true}
    {"kill_memory_checked": true}
    {"impact_derived": true}
    {"scope_snapshot_pinned": true}
    {"in_scope": true}
    {"report_sections_present": {"n": 3}}
    {"claim_traceability": {"min_claims": 1}}
    {"human_approved": true}
    {"gate_not_self_approved": true}

Every gate's predicate is stored on the ``gate`` row inside the database, so an
auditor can read *why* a branch advanced without reading Python.
"""
from __future__ import annotations

from typing import Any

from ..constants import GATE_CHAIN

def _prev(gate_id: str) -> list[dict[str, Any]]:
    i = GATE_CHAIN.index(gate_id)
    if i == 0:
        return []
    return [{"previous_gate_passed": GATE_CHAIN[i - 1]}]


GATE_PREDICATES: dict[str, dict[str, Any]] = {
    # 1 ---------------------------------------------------------------- scope
    "scope_admission": {
        "all": _prev("scope_admission") + [
            {"scope_snapshot_pinned": True},
            {"in_scope": True},
            {"has_node": "branch"},
        ]
    },
    # 2 -------------------------------------------------------- surface map
    "surface_mapping": {
        "all": _prev("surface_mapping") + [
            {"has_node": "scope_snapshot"},
            {"min_nodes": {"kind": "evidence", "n": 1}},
            {"edge_exists": {"rel": "TESTS", "src_kind": "experiment",
                             "dst_kind": "claim"}},
            {"edge_exists": {"rel": "APPLIES_TO_COMMIT",
                             "src_kind": "evidence", "dst_kind": "commit"}},
        ]
    },
    # 3 --------------------------------------------------- invariants
    "invariant_definition": {
        "all": _prev("invariant_definition") + [
            {"min_nodes": {"kind": "claim", "n": 2}},
            {"claim_class_present": "substantive"},
            {"assumptions_declared": True},
        ]
    },
    # 4 ------------------------------------------- actor and authority model
    "actor_authority": {
        "all": _prev("actor_authority") + [
            {"claim_class_present": "scope"},
            {"actor_model_declared": True},
            {"edge_exists": {"rel": "DEPENDS_ON", "src_kind": "claim",
                             "dst_kind": "assumption"}},
        ]
    },
    # 5 -------------------------------------------------------- reachability
    "reachability": {
        "all": _prev("reachability") + [
            {"evidence_kind": {"kind": "metadata", "n": 1}},
            {"edge_exists": {"rel": "SUPPORTS", "src_kind": "evidence",
                             "dst_kind": "claim"}},
            {"experiment_requested": True},
        ]
    },
    # 6 ------------------------------------------------------- exploit chain
    "exploit_chain": {
        "all": _prev("exploit_chain") + [
            {"min_nodes": {"kind": "claim", "n": 3}},
            {"edge_chain": {"rel": "DEPENDS_ON", "min_len": 2}},
            {"orbit_sealed": "attack"},
        ]
    },
    # 7 ---------------------------------------------------------- local proof
    "local_proof": {
        "all": _prev("local_proof") + [
            {"experiment_outcome": {"outcome": "pass", "n": 1}},
            {"proof_binding_complete": True},
            {"artifact_hashed": {"n": 1}},
        ]
    },
    # 8 --------------------------------------- falsification and controls
    "falsification": {
        "all": _prev("falsification") + [
            {"control_result": {"result": "held", "n": 1}},
            {"orbit_sealed": "defense"},
            {"orbits_merged": True},
            {"no_open_contradictions": True},
        ]
    },
    # 9 ------------------------------------------- novelty / duplicate
    "novelty": {
        "all": _prev("novelty") + [
            {"novelty_fingerprint": True},
            {"duplicate_checked": True},
            {"kill_memory_checked": True},
            {"orbit_sealed": "history"},
        ]
    },
    # 10 ------------------------------------------------- impact / economics
    "impact": {
        "all": _prev("impact") + [
            {"impact_derived": True},
            {"orbit_sealed": "impact"},
            {"edge_exists": {"rel": "DEPENDS_ON", "src_kind": "impact",
                             "dst_kind": "claim"}},
        ]
    },
    # 11 ------------------------------------------------------ reportability
    "reportability": {
        "all": _prev("reportability") + [
            {"report_sections_present": {"n": 3}},
            {"claim_traceability": {"min_claims": 1}},
            {"no_open_contradictions": True},
        ]
    },
    # 12 ------------------------------------------------------- final QC
    "final_qc": {
        "all": _prev("final_qc") + [
            {"independent_verifier": True},
            {"independent_verifier_role": "human"},
            {"verifier_not_author": True},
            {"orphan_report_claim_free": True},
            {"human_approved": True},
            {"gate_not_self_approved": True},
        ]
    },
}

# Gates whose *decisive* evidence must be produced by an activity other than the
# one approving it. Enforced structurally, not by convention.
def requires_independent_approver(gate_id: str) -> bool:
    return gate_id in {"local_proof", "falsification", "novelty", "impact",
                       "reportability", "final_qc"}

# Gate that can be re-entered when a branch goes STALE (source/scope drift).
REVALIDATION_GATES = ("local_proof", "falsification", "final_qc")
