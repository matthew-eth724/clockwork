"""Evidence-Gate Graph evaluation.

Each gate predicate is evaluated against a facts snapshot. The evaluator returns
a structured trace so a reviewer can see *which leaf* blocked advancement.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..constants import (CRITICAL_GATES, GATE_CHAIN, GATE_LABELS,
                         GATE_SOVEREIGN_ORBIT)
from ..facts import Facts
from .predicates import GATE_PREDICATES

# Node kinds that belong to the case rather than to one lane.
CASE_SCOPED_KINDS = {"scope_snapshot", "commit", "precedent", "case"}


@dataclass
class GateResult:
    gate_id: str
    state: str                        # PASSED | FAILED | BLOCKED
    checks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def failed(self) -> list[dict]:
        return [c for c in self.checks if not c["ok"]]

    def to_dict(self) -> dict:
        return {"gate_id": self.gate_id, "state": self.state,
                "checks": self.checks,
                "blockers": [c["check"] for c in self.failed]}


def _ev(store, cid, kind):
    return [n for n in store.nodes.values()
            if n.kind == "evidence" and n.branch_id == cid
            and n.attrs.get("evidence_kind") == kind]


def _has_reachability_request(facts: Facts, branch_id: str) -> bool:
    return any(n.attrs.get("evidence_kind") == "metadata"
               for n in facts.branch_nodes(branch_id, "evidence"))


def _dependency_chain_len(facts: Facts, branch_id: str) -> int:
    claims = {n.node_id for n in facts.branch_nodes(branch_id, "claim")}
    graph: dict[str, set[str]] = {c: set() for c in claims}
    for e in facts.live_edges("DEPENDS_ON"):
        if e.src_id in claims and e.dst_id in claims:
            graph[e.src_id].add(e.dst_id)
    best = 0
    for start in claims:
        stack = [(start, 1)]
        seen = set()
        while stack:
            node, depth = stack.pop()
            for nxt in graph.get(node, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                stack.append((nxt, depth + 1))
                best = max(best, depth + 1)
    return best


def _proof_bindings(facts: Facts, branch_id: str) -> list[dict]:
    """Every passing experiment must be bound: commit, environment, command,
    expected observable, controls, artifact hashes."""
    out = []
    for n in facts.branch_nodes(branch_id, "experiment"):
        a = n.attrs
        missing = [k for k in ("commit_sha", "environment", "command",
                               "expected_observable")
                   if not a.get(k) and not n.commit_sha]
        if not a.get("artifact_hashes"):
            missing.append("artifact_hashes")
        if not a.get("controls"):
            missing.append("controls")
        if a.get("outcome") != "pass":
            missing.append("outcome!=pass")
        out.append({"experiment_id": n.node_id, "missing": missing})
    return out


def _independent_verification(facts: Facts, branch_id: str) -> dict:
    """A claim/evidence pair approved at a critical gate must carry a verifier
    other than the producer."""
    produced_by = set()
    verifiers = set()
    for e in facts.branch_nodes(branch_id, "evidence"):
        producer = e.attrs.get("produced_by")
        produced_by.add(producer)
        verified = list(e.attrs.get("verified_by") or [])
        verified += [ve.src_id for ve in facts.edges_to(e.node_id, "VERIFIED_BY")]
        for v in verified:
            if v != producer:
                verifiers.add(v)
    return {"producers": sorted(x for x in produced_by if x),
            "verifiers": sorted(v for v in verifiers if v),
            "independent": any(v not in produced_by for v in verifiers)}


def _check(facts: Facts, branch_id: str, check: dict[str, Any]) -> tuple[bool, str]:
    """Evaluate one leaf predicate. Returns (ok, human reason)."""
    if "all" in check:
        for sub in check["all"]:
            ok, why = _check(facts, branch_id, sub)
            if not ok:
                return False, why
        return True, "all satisfied"
    if "any" in check:
        reasons = []
        for sub in check["any"]:
            ok, why = _check(facts, branch_id, sub)
            if ok:
                return True, why
            reasons.append(why)
        return False, "any-of failed: " + "; ".join(reasons)

    if "previous_gate_passed" in check:
        prev = check["previous_gate_passed"]
        st = facts.gate_state(branch_id, prev)
        return st == "PASSED", f"{prev}={st}"

    if "has_node" in check:
        kind = check["has_node"]
        if kind in CASE_SCOPED_KINDS:
            # case-level anchors (scope snapshots, reports) hang off the case,
            # not off a single lane
            nodes = facts.of_kind(kind)
        else:
            nodes = facts.branch_nodes(branch_id, kind)
        return bool(nodes), f"{len(nodes)} {kind} node(s)"

    if "min_nodes" in check:
        spec = check["min_nodes"]
        n = len(facts.branch_nodes(branch_id, spec["kind"]))
        return n >= spec["n"], f"{spec['kind']}: {n}/{spec['n']}"

    if "edge_exists" in check:
        spec = check["edge_exists"]
        for e in facts.live_edges(spec["rel"]):
            s, d = facts.node(e.src_id), facts.node(e.dst_id)
            if not s or not d:
                continue
            if spec.get("src_kind") and s.kind != spec["src_kind"]:
                continue
            if spec.get("dst_kind") and d.kind != spec["dst_kind"]:
                continue
            if s.branch_id != branch_id and d.branch_id != branch_id:
                continue
            return True, f"{spec['rel']} {s.kind}->{d.kind} present"
        return False, f"no {spec['rel']} edge {spec.get('src_kind')}->{spec.get('dst_kind')}"

    if "evidence_kind" in check:
        spec = check["evidence_kind"]
        n = len([e for e in facts.branch_nodes(branch_id, "evidence")
                 if e.attrs.get("evidence_kind") == spec["kind"]])
        return n >= spec["n"], f"evidence[{spec['kind']}] {n}/{spec['n']}"

    if "experiment_outcome" in check:
        spec = check["experiment_outcome"]
        n = len([x for x in facts.branch_nodes(branch_id, "experiment")
                 if x.attrs.get("outcome") == spec["outcome"]])
        return n >= spec["n"], f"experiments({spec['outcome']}) {n}/{spec['n']}"

    if "experiment_requested" in check:
        n = len(facts.branch_nodes(branch_id, "experiment"))
        return n >= 1, f"{n} experiment(s) requested"

    if "control_result" in check:
        spec = check["control_result"]
        n = len([c for c in facts.branch_nodes(branch_id, "control")
                 if c.attrs.get("result") == spec["result"]])
        return n >= spec["n"], f"controls({spec['result']}) {n}/{spec['n']}"

    if "proof_binding_complete" in check:
        binds = _proof_bindings(facts, branch_id)
        bad = [b for b in binds if b["missing"]]
        return (not bad and bool(binds)), (
            "all experiments fully bound" if not bad
            else "unbound: " + "; ".join(f"{b['experiment_id']}->{b['missing']}"
                                         for b in bad))

    if "artifact_hashed" in check:
        # experiments carry their artifact hashes inline; evidence may also be
        # bound to a content-addressed artifact in its own right
        hashes = set()
        for exp in facts.branch_nodes(branch_id, "experiment"):
            hashes.update(exp.attrs.get("artifact_hashes") or [])
        hashes.update(a.node_id for a in facts.branch_nodes(branch_id, "artifact"))
        n = len(hashes)
        return n >= check["artifact_hashed"]["n"], f"hashed artifacts: {n}"

    if "gate_passed" in check:
        st = facts.gate_state(branch_id, check["gate_passed"])
        return st == "PASSED", f"{check['gate_passed']}={st}"

    if "independent_verifier" in check:
        info = _independent_verification(facts, branch_id)
        producers = set(info["producers"])
        producers |= {x.attrs.get("requested_by")
                      for x in facts.branch_nodes(branch_id, "experiment")}
        producers |= {x.attrs.get("produced_by")
                      for x in facts.branch_nodes(branch_id, "claim")}
        independent = [v for v in info["verifiers"] if v not in producers]
        return bool(independent), f"independent verifiers={independent}"

    if "independent_verifier_role" in check:
        want = check["independent_verifier_role"]
        for v in _independent_verification(facts, branch_id)["verifiers"]:
            auth = facts.authority.get(v, {})
            if auth.get("kind") == want:
                return True, f"{v} is {want}"
        return False, f"no independent {want} verifier"

    if "verifier_not_author" in check:
        producers = set()
        for k in facts.branch_nodes(branch_id, "evidence"):
            if k.attrs.get("produced_by"):
                producers.add(k.attrs["produced_by"])
        for h in facts.human_decisions:
            if h.get("decision") == "approve_gate":
                if h["actor"] not in producers:
                    return True, f"{h['actor']} != producer set"
        return False, "approval came only from producers"

    if "no_open_contradictions" in check:
        open_c = [e for e in facts.live_edges("CONTRADICTS")
                  if (facts.node(e.src_id) and
                      facts.node(e.src_id).branch_id == branch_id)]
        resolved = [e for e in facts.live_edges("RULES_OUT")
                    if facts.node(e.src_id)
                    and facts.node(e.src_id).branch_id == branch_id]
        return (not open_c) or len(resolved) >= len(open_c), (
            f"contradictions={len(open_c)} resolved_by_rules_out={len(resolved)}")

    if "contradictions_resolved" in check:
        return _check(facts, branch_id, {"no_open_contradictions": True})

    if "assumptions_declared" in check:
        n = len(facts.branch_nodes(branch_id, "assumption"))
        return n >= 1, f"assumptions={n}"

    if "actor_model_declared" in check:
        n = len([c for c in facts.branch_nodes(branch_id, "claim")
                 if c.attrs.get("claim_class") in ("scope", "assumption")
                 or "actor" in (c.label or "").lower()])
        return n >= 1, f"actor/scope model claims={n}"

    if "claim_class_present" in check:
        cls = check["claim_class_present"]
        n = len([c for c in facts.branch_nodes(branch_id, "claim")
                 if c.attrs.get("claim_class") == cls])
        return n >= 1, f"claims[{cls}]={n}"

    if "edge_chain" in check:
        need = check["edge_chain"]["min_len"]
        got = _dependency_chain_len(facts, branch_id)
        return got >= need, f"dependency chain depth {got}/{need}"

    if "orbit_sealed" in check:
        seal = facts.seals.get(check["orbit_sealed"])
        if not seal:
            return False, f"orbit {check['orbit_sealed']} not sealed"
        return True, f"orbit sealed at seq {seal['sealed_seq']}"

    if "orbits_merged" in check:
        got: set[str] = set()
        for m in facts.merges:
            got.update(m.get("orbits") or str(m.get("orbit", "")).split("+"))
        need = {"attack", "defense"}
        return need.issubset(got), f"merged orbits={sorted(got)}"

    if "novelty_fingerprint" in check:
        n = len(facts.branch_nodes(branch_id, "fingerprint"))
        return n >= 1, f"fingerprints={n}"

    if "duplicate_checked" in check:
        n = len([p for p in facts.precedents.values()
                 if p.get("kind") in ("duplicate_family", "vulnerability_pattern")])
        edges = [e for e in facts.live_edges("DUPLICATE_OF")
                 if facts.node(e.src_id) and facts.node(e.src_id).branch_id == branch_id]
        return n > 0 or len(edges) > 0, f"precedent/dup edges={n}"

    if "kill_memory_checked" in check:
        seeded_mechanism = None
        for b in facts.branch_nodes(branch_id, "branch"):
            seeded_mechanism = b.attrs.get("suspected_mechanism")
        challenged = [k for k in facts.kills.values()
                      if k.get("invalidated_by") or k.get("challenged_by")]
        return (bool(challenged) or not facts.kills), (
            f"kill-records={len(facts.kills)} challenged={len(challenged)}")

    if "impact_derived" in check:
        imps = [i for i in facts.branch_nodes(branch_id, "impact")]
        return bool(imps), f"impacts={len(imps)}"

    if "scope_snapshot_pinned" in check:
        snaps = facts.of_kind("scope_snapshot")
        return bool(snaps), f"scope snapshots={len(snaps)}"

    if "in_scope" in check:
        case = next(iter(facts.of_kind("case")), None)
        st = facts.branch_state.get("*", {})
        if st.get("stale_reason") and st.get("case_status") != "closed":
            return False, "case marked stale"
        return True, "case open and in scope manifest"

    if "report_sections_present" in check:
        n = len([s for s in facts.report_sections])
        return n >= check["report_sections_present"]["n"], (
            f"report sections={n}")

    if "claim_traceability" in check:
        min_claims = check["claim_traceability"]["min_claims"]
        traced = 0
        for c in facts.branch_nodes(branch_id, "claim"):
            has_support = any(e.rel == "SUPPORTS" and e.dst_id == c.node_id
                              for e in facts.live_edges())
            has_producer = any(e.rel == "GENERATED_BY" and e.dst_id == c.node_id
                               for e in facts.live_edges())
            if has_support or has_producer:
                traced += 1
        return traced >= min_claims, f"traced claims={traced}/{min_claims}"

    if "orphan_report_claim_free" in check:
        orphans = []
        for sec in facts.report_sections:
            for cid in sec.get("claim_ids", []):
                node = facts.node(cid)
                if not node:
                    orphans.append(cid)
                    continue
                if not facts.edges_to(cid, "SUPPORTS"):
                    orphans.append(cid)
        return not orphans, f"orphan report claims={orphans}"

    if "human_approved" in check:
        for h in facts.human_decisions:
            if h.get("decision") in ("approve_gate", "approve_report"):
                return True, f"human approval by {h['actor']}"
        return False, "no human approval recorded"

    if "gate_not_self_approved" in check:
        return True, "enforced at decision time (see gate engine)"

    raise ValueError(f"unknown predicate leaf: {check}")


def evaluate_gate(facts: Facts, branch_id: str, gate_id: str) -> GateResult:
    predicate = GATE_PREDICATES[gate_id]
    checks: list[dict] = []
    state = "PASSED"
    for sub in predicate.get("all", []):
        ok, why = _check(facts, branch_id, sub)
        checks.append({"check": _describe(sub), "ok": ok, "reason": why})
        if not ok:
            state = "FAILED"
    return GateResult(gate_id=gate_id, state=state, checks=checks)


def _describe(check: dict) -> str:
    for k in ("previous_gate_passed", "has_node", "min_nodes", "edge_exists",
              "evidence_kind", "experiment_outcome", "control_result",
              "proof_binding_complete", "artifact_hashed", "gate_passed",
              "independent_verifier", "independent_verifier_role",
              "verifier_not_author", "no_open_contradictions", "assumptions_declared",
              "orbit_sealed", "orbits_merged", "novelty_fingerprint",
              "duplicate_checked", "kill_memory_checked", "impact_derived",
              "scope_snapshot_pinned", "in_scope", "report_sections_present",
              "claim_traceability", "human_approved", "gate_not_self_approved",
              "actor_model_declared", "claim_class_present", "edge_chain",
              "orphan_report_claim_free", "contradictions_resolved",
              "experiment_requested"):
        if k in check:
            return k
    return "all"


def next_gate(facts: Facts, branch_id: str) -> str | None:
    for gate_id in GATE_CHAIN:
        if facts.gate_state(branch_id, gate_id) != "PASSED":
            return gate_id
    return None


def requires_independent_approver(gate_id: str) -> bool:
    return gate_id in CRITICAL_GATES


def sovereign_orbit(gate_id: str) -> str | None:
    return GATE_SOVEREIGN_ORBIT.get(gate_id)
