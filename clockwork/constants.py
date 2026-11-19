"""Canonical vocabularies for Clockwork Engineering.

Nothing here is advisory: the gate predicate language, the event catalogue and
the relationship set are the machine-readable contract the runtime enforces.
"""
from __future__ import annotations

EVENT_TYPES = (
    "candidate_seeded",
    "claim_proposed",
    "evidence_added",
    "claim_supported",
    "claim_contradicted",
    "experiment_requested",
    "experiment_completed",
    "control_completed",
    "gate_passed",
    "gate_failed",
    "branch_forked",
    "branch_merged",
    "branch_killed",
    "branch_parked",
    "case_marked_stale",
    "report_packaged",
    "human_decision",
    # -- supporting event types (still append-only, still replayable) --
    "case_opened",
    "artifact_stored",
    "edge_added",
    "edge_retired",
    "orbit_sealed",
    "orbit_merged",
    "agent_registered",
    "experiment_dispatched",
    "kill_recorded",
    "kill_challenged",
    "precedent_abstracted",
    "assumption_declared",
    "scope_snapshot_captured",
    "impact_derived",
    "fix_recorded",
    "report_section_generated",
    "case_parked",
    "case_closed",
)

# Events that mutate graph state in a way that can re-open a gate.
GATE_RELEVANT_EVENTS = frozenset({
    "evidence_added",
    "claim_supported",
    "claim_contradicted",
    "experiment_completed",
    "control_completed",
    "case_marked_stale",
    "branch_forked",
    "branch_merged",
    "human_decision",
})

RELATIONSHIPS = (
    "SUPPORTS",
    "CONTRADICTS",
    "DEPENDS_ON",
    "TESTS",
    "RULES_OUT",
    "GENERATED_BY",
    "VERIFIED_BY",
    "BLOCKED_BY",
    "INVALIDATED_BY",
    "APPLIES_TO_COMMIT",
    "ABSTRACTS_TO",
    "DUPLICATE_OF",
    "FIXED_BY",
    "INCLUDED_IN",
)

# Provenance-bearing relations: an edge of this type is what makes a report
# claim traceable to a source reference.
PROVENANCE_RELATIONS = frozenset({
    "SUPPORTS", "TESTS", "GENERATED_BY", "VERIFIED_BY", "INCLUDED_IN",
})

ORBITS = ("attack", "defense", "history", "impact")

# Ordered gate chain. A branch advances one gate at a time; skipping is
# structurally impossible because every predicate can reference gate N-1.
GATE_CHAIN = (
    "scope_admission",     # 1  Scope Admission
    "surface_mapping",     # 2  Surface Mapping
    "invariant_definition",  # 3 Invariant Definition
    "actor_authority",     # 4  Actor and Authority Model
    "reachability",        # 5  Reachability
    "exploit_chain",       # 6  Exploit Chain
    "local_proof",         # 7  Local Proof
    "falsification",       # 8  Falsification and Controls
    "novelty",             # 9  Novelty and Duplicate Analysis
    "impact",              # 10 Impact and Economics
    "reportability",       # 11 Reportability
    "final_qc",            # 12 Final QC and Packaging
)

GATE_LABELS = {
    "scope_admission": "Scope Admission",
    "surface_mapping": "Surface Mapping",
    "invariant_definition": "Invariant Definition",
    "actor_authority": "Actor and Authority Model",
    "reachability": "Reachability",
    "exploit_chain": "Exploit Chain",
    "local_proof": "Local Proof",
    "falsification": "Falsification and Controls",
    "novelty": "Novelty and Duplicate Analysis",
    "impact": "Impact and Economics",
    "reportability": "Reportability",
    "final_qc": "Final QC and Packaging",
}

# Gates whose evidence is *critical*: cannot be approved by the same activity
# (agent/orbit) that produced it.
CRITICAL_GATES = frozenset({
    "local_proof",
    "falsification",
    "novelty",
    "impact",
    "reportability",
    "final_qc",
})

# Which orbit is a sovereign producer for which gate. The orbit that produces
# a gate's decisive evidence may not also approve that gate.
GATE_SOVEREIGN_ORBIT = {
    "scope_admission": "system",
    "surface_mapping": "attack",
    "invariant_definition": "attack",
    "actor_authority": "attack",
    "reachability": "attack",
    "exploit_chain": "attack",
    "local_proof": "attack",
    "falsification": "defense",
    "novelty": "history",
    "impact": "impact",
    "reportability": "impact",
    "final_qc": None,          # QC must be human / non-producing reviewer
}

PROOF_STATES = ("RED", "YELLOW", "GREEN", "STALE")
LANE_STATUS = ("open", "parked", "merged", "killed")

# CI-like severity of failure: RED = proof fails, YELLOW = proof works but not
# all gates are green, GREEN = everything passes, STALE = bindings moved.
def derive_proof_state(*, proof_passing: bool, gates_passed: bool, stale: bool) -> str:
    if stale:
        return "STALE"
    if not proof_passing:
        return "RED"
    return "GREEN" if gates_passed else "YELLOW"
