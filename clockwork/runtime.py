"""Clockwork Engineering runtime.

All state changes flow through :class:`Runtime`, which:

1. validates the actor's authority against the standing policy (no agent may
   expand its own authority, approve its own critical evidence, submit a report,
   contact a target, or erase contradictory evidence);
2. appends a canonical ``case_event``;
3. re-projects the graph and re-evaluates gate state.

There is deliberately no API that mutates projected tables directly.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any

from .constants import (CRITICAL_GATES, GATE_CHAIN, GATE_LABELS,
                        GATE_SOVEREIGN_ORBIT, ORBITS, derive_proof_state)
from .context import ContextPacket, cut_packet
from .facts import Facts, FactNode
from .gates.engine import evaluate_gate, next_gate
from .gates.predicates import REVALIDATION_GATES
from .killmemory import (KillCheck, check_against_kills,
                         validate_kill_record)
from .novelty import compare, compute_fingerprint, components
from .projection import project
from .shards import shard_for, worker_eligible
from .store import Store

PENDING = object()


def _orbit_of(actor_id: str) -> str:
    """Activity identity convention.

    Accepted shapes include ``<case>:<orbit>``, ``<orbit>-<n>``,
    ``<case>:<orbit>-<n>`` and the agent's registered display pool. Orbit is an
    *activity* property, never an authorization claim: it only decides whether
    already-sealed output may be mutated.
    """
    parts = re.split(r"[:._/]", actor_id)
    tokens = set(parts)
    for token in parts:
        tokens.update(token.split("-"))
    for orbit in ORBITS:
        if orbit in tokens:
            return orbit
    # capability is the fallback: ``orbit:<name>``
    caps = globals().get("_CAP_INDEX", {})
    return caps.get(actor_id, "system")


class AuthorityError(Exception):
    """Raised when an action would exceed an actor's standing authority."""


class GateError(Exception):
    """Raised when a gate transition is not permitted by the graph."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Runtime:
    def __init__(self, store: Store | None = None):
        self.store = store or Store()
        self._facts_cache: dict[str, tuple[int, Facts]] = {}

    # ------------------------------------------------------------------ init
    def boot(self) -> None:
        self.store.init()

    def close(self) -> None:
        self.store.close()

    # ---------------------------------------------------------------- agents
    def register_agent(self, agent_id: str, kind: str, display_name: str,
                       requested_caps: list[str] | None = None) -> None:
        caps = requested_caps or []
        # Standing policy ceiling: no actor may request submission, contact or
        # self-approval capabilities, whoever asks.
        forbidden = {"submit_report", "contact_target", "approve_own_evidence",
                     "expand_authority", "erase_evidence"}
        bad = forbidden & set(caps)
        if bad:
            raise AuthorityError(f"capabilities not grantable by policy: {sorted(bad)}")
        self.store.q(
            """INSERT INTO cw.agent (agent_id, kind, display_name, requested_caps)
               VALUES (%s,%s,%s,%s) ON CONFLICT (agent_id) DO NOTHING""",
            (agent_id, kind, display_name, caps))
        if not self.store.q1(
                "SELECT 1 AS x FROM cw.case_event WHERE event_type='agent_registered' "
                "AND payload->>'agent_id'=%s LIMIT 1", (agent_id,)):
            # registration is itself an event on a synthetic system case
            self.store.append("__system__", "agent_registered", agent_id,
                              {"agent_id": agent_id, "kind": kind, "caps": caps},
                              orbit="system")

    def authority(self, agent_id: str) -> dict:
        row = self.store.q1("SELECT * FROM cw.agent WHERE agent_id=%s", (agent_id,))
        if not row:
            raise AuthorityError(f"unknown actor {agent_id!r}")
        return row

    def _assert_can_produce(self, agent_id: str, case_id: str, orbit: str) -> None:
        auth = self.authority(agent_id)
        if auth["kind"] == "human":
            return
        caps = set(auth["requested_caps"] or [])
        if caps and not ({"produce_evidence", "run_experiment", f"orbit:{orbit}"}
                         & caps):
            raise AuthorityError(f"{agent_id} lacks production capability for {orbit}")

    def _lane_is_fresh(self, facts: Facts, branch_id: str, seal: dict) -> bool:
        """A lane is fresh if its investigative activity began after the seal.

        A lane *declared* at case open but *seeded* after a seal is still a new
        hypothesis — declaration is bookkeeping, seeding is the investigative act.
        """
        node = facts.node(branch_id)
        if node is None:
            return False
        seeded_seq = (node.attrs or {}).get("seeded_seq")
        start = seeded_seq or node.seq
        return start > seal["sealed_seq"]

    def _assert_node_unsealed(self, facts: Facts, node_id: str, actor: str) -> None:
        """A node sealed with its orbit is frozen; appending to it is a mutation."""
        for orbit, seal in facts.seals.items():
            node = facts.nodes.get(node_id)
            if node and node.orbit == orbit and node.seq <= seal["sealed_seq"]:
                raise AuthorityError(
                    f"{node_id} was sealed with orbit {orbit} at seq "
                    f"{seal['sealed_seq']}; {actor} may not mutate it")

    def _producing_orbit(self, case_id: str, actor: str) -> str:
        """Orbit of an activity: from its id, else from its granted capability."""
        orbit = _orbit_of(actor)
        if orbit != "system":
            return orbit
        caps = set(self.authority(actor)["requested_caps"] or [])
        for cap in caps:
            if cap.startswith("orbit:"):
                return cap.split(":", 1)[1]
        return "system"

    def _assert_not_sealed_output(self, facts: Facts, branch_id: str,
                                  actor: str) -> None:
        """Sealing is a one-way barrier with fork semantics.

        ``seal`` freezes every node up to the seal sequence. After sealing, an
        activity may continue only on a lane created *after* the seal; pre-seal
        output is never mutated in place.
        """
        seal = facts.seals.get(self._producing_orbit(facts.case_id, actor))
        if not seal:
            return
        if seal["sealed_seq"] <= (facts.branch_state.get(branch_id, {})
                                  .get("created_seq", 0)):
            return
        if not self._lane_is_fresh(facts, branch_id, seal):
            raise AuthorityError(
                f"orbit {self._producing_orbit(facts.case_id, actor)!r} "
                f"sealed at seq {seal['sealed_seq']}; {actor} may not mutate "
                f"sealed output on {branch_id} (fork a fresh lane instead)")

    # ----------------------------------------------------------------- cases
    def open_case(self, case_id: str, title: str, repos: list[str],
                  scope_snapshot: dict, actor: str,
                  branches: list[dict] | None = None) -> dict:
        shard = shard_for(case_id)
        branches = branches or [{"branch_id": "main", "label": "main"}]
        payload = {"case_id": case_id, "title": title, "repos": repos,
                   "shard": shard, "branches": branches}
        ev = self.store.append(case_id, "case_opened", actor, payload)
        self.store.q(
            """INSERT INTO cw.case (case_id, shard_id, title, repo_ids, status,
                                    created_seq)
               VALUES (%s,%s,%s,%s,'open',%s)
               ON CONFLICT (case_id) DO NOTHING""",
            (case_id, shard, title, repos, ev["seq"]))
        # artifact replication: primary on the case shard, replica on a
        # deterministically chosen second shard for read locality
        replica = (shard + 1) % 64
        for sid, role in ((shard, "primary"), (replica, "replica")):
            self.store.q(
                """INSERT INTO cw.case_artifact_replica (case_id, shard_id, role,
                        pinned_repo)
                   VALUES (%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
                (case_id, sid, role, repos[0] if repos else None))
        snap_id = scope_snapshot.get("scope_snapshot_id", f"scope:{case_id}:0")
        self.store.append(case_id, "scope_snapshot_captured", actor, {
            "scope_snapshot_id": snap_id,
            "repo_id": scope_snapshot.get("repo_id", repos[0] if repos else ""),
            "commit_sha": scope_snapshot.get("commit_sha", "0" * 40),
            "manifest": scope_snapshot,
        }, orbit="system")
        return ev

    def facts(self, case_id: str, upto_seq: int | None = None) -> Facts:
        events = self.store.events(case_id, upto_seq)
        key = (events[-1]["seq"] if events else 0)
        cached = self._facts_cache.get(case_id)
        if cached and cached[0] == key:
            return cached[1]
        facts = project(events)
        self._hydrate_authority(facts)
        self._facts_cache[case_id] = (key, facts)
        return facts

    def _hydrate_authority(self, facts: Facts) -> None:
        """Agent identity lives in the global registry (its registrations are
        events on the synthetic ``__system__`` case). Decisions still read only
        replayable state."""
        for row in self.store.q("SELECT agent_id, kind, requested_caps FROM cw.agent"):
            facts.authority.setdefault(row["agent_id"], {
                "kind": row["kind"],
                "caps": set(row["requested_caps"] or []),
                "seq": 0})

    def _append(self, case_id: str, event_type: str, actor: str, payload: dict,
                orbit: str = "system") -> dict:
        ev = self.store.append(case_id, event_type, actor, payload, orbit)
        self._facts_cache.pop(case_id, None)
        return ev

    # ------------------------------------------------------------ placement
    def placement(self, case_id: str) -> dict:
        shard = shard_for(case_id)
        row = self.store.q1("SELECT * FROM cw.shard_placement WHERE shard_id=%s",
                            (shard,))
        replicas = self.store.q(
            "SELECT shard_id, role FROM cw.case_artifact_replica WHERE case_id=%s",
            (case_id,))
        return {"case_id": case_id, "shard_id": shard,
                "physical": row["physical_dsn"] if row else None,
                "worker_pool": row["worker_pool"] if row else None,
                "active": bool(row and row["active"]),
                "replicas": [dict(r) for r in replicas]}

    def schedule(self, case_id: str, branch_id: str, worker: dict) -> dict:
        facts = self.facts(case_id)
        pl = self.placement(case_id)
        branch = facts.node(branch_id)
        repo = branch.attrs.get("repo_id") if branch else None
        ok, why = worker_eligible(
            {"active": pl["active"], "worker_pool": pl["worker_pool"],
             "repo_need": [repo] if repo else []}, worker)
        gate = next_gate(facts, branch_id)
        return {"case_id": case_id, "branch_id": branch_id,
                "eligible": ok, "reason": why, "shard_id": pl["shard_id"],
                "next_gate": gate, "next_gate_label": GATE_LABELS.get(gate or "", None)}

    # --------------------------------------------------------------- seeding
    def seed_candidate(self, case_id: str, branch_id: str, actor: str,
                       suspected_mechanism: str, repo_id: str,
                       commit_range: str, orbit: str = "attack",
                       label: str | None = None) -> dict:
        facts = self.facts(case_id)
        return self._append(case_id, "candidate_seeded", actor, {
            "branch_id": branch_id, "label": label or branch_id,
            "suspected_mechanism": suspected_mechanism,
            "repo_id": repo_id, "commit_range": commit_range,
            # the lane's producing activity fixes its orbit; a seed is an
            # attack-shaped hypothesis unless stated otherwise
            "orbit": orbit,
        }, orbit=orbit)

    # ---------------------------------------------------------------- claims
    def propose_claim(self, case_id: str, branch_id: str, claim_id: str,
                      statement: str, actor: str, orbit: str = "attack",
                      claim_class: str = "substantive",
                      depends_on: list[str] | None = None,
                      confidence: float | None = None) -> dict:
        facts = self.facts(case_id)
        self._assert_not_sealed_output(facts, branch_id, actor)
        self._assert_can_produce(actor, case_id, orbit)
        return self._append(case_id, "claim_proposed", actor, {
            "claim_id": claim_id, "branch_id": branch_id,
            "statement": statement, "claim_class": claim_class,
            "depends_on": depends_on or [],
            "confidence": 0.5 if confidence is None else confidence,
        }, orbit=orbit)

    def declare_assumption(self, case_id: str, branch_id: str, assumption_id: str,
                           statement: str, actor: str, falsifiable_by: list[str],
                           orbit: str = "attack") -> dict:
        if not falsifiable_by:
            raise AuthorityError("an assumption must state how it could be falsified")
        facts = self.facts(case_id)
        self._assert_not_sealed_output(facts, branch_id, actor)
        return self._append(case_id, "assumption_declared", actor, {
            "assumption_id": assumption_id, "branch_id": branch_id,
            "statement": statement, "falsifiable_by": falsifiable_by,
        }, orbit=orbit)

    def support_claim(self, case_id: str, claim_id: str, evidence_ids: list[str],
                      actor: str, orbit: str = "attack") -> dict:
        facts = self.facts(case_id)
        if facts.exists(claim_id):
            self._assert_node_unsealed(facts, claim_id, actor)
            self._assert_not_sealed_output(
                facts, facts.node(claim_id).branch_id or "", actor)
        for eid in evidence_ids:
            node = facts.node(eid)
            if not node or node.kind != "evidence":
                raise GateError(f"cannot support {claim_id}: {eid} is not evidence")
            self._assert_node_unsealed(facts, eid, actor)
        return self._append(case_id, "claim_supported", actor,
                            {"claim_id": claim_id, "evidence_ids": evidence_ids},
                            orbit=orbit)

    def contradict_claim(self, case_id: str, claim_id: str,
                         evidence_ids: list[str], actor: str,
                         orbit: str = "defense", reason: str = "") -> dict:
        facts = self.facts(case_id)
        branch_id = getattr(facts.node(claim_id), "branch_id", None) \
            if facts.node(claim_id) else None
        if branch_id:
            self._assert_not_sealed_output(facts, branch_id, actor)
        # Contradictory evidence can never be erased: only recorded and,
        # if genuinely refuted, *ruled out* with new evidence.
        return self._append(case_id, "claim_contradicted", actor, {
            "claim_id": claim_id, "evidence_ids": evidence_ids,
            "reason": reason}, orbit=orbit)

    # -------------------------------------------------------------- evidence
    def add_evidence(self, case_id: str, branch_id: str, evidence_id: str,
                     actor: str, kind: str = "metadata",
                     supports: list[str] | None = None,
                     contradicts: list[str] | None = None,
                     rules_out: list[str] | None = None,
                     commit_sha: str | None = None,
                     source_ref: str | None = None,
                     artifact: bytes | None = None,
                     artifact_media_type: str = "text/plain",
                     orbit: str = "attack", label: str | None = None,
                     verifies: list[str] | None = None) -> dict:
        facts = self.facts(case_id)
        self._assert_not_sealed_output(facts, branch_id, actor)
        self._assert_can_produce(actor, case_id, orbit)
        payload: dict[str, Any] = {
            "evidence_id": evidence_id, "branch_id": branch_id,
            "kind": kind, "supports": supports or [],
            "contradicts": contradicts or [], "rules_out": rules_out or [],
            "commit_sha": commit_sha, "source_ref": source_ref,
            "label": label or evidence_id,
        }
        if artifact is not None:
            aid = self.store.put_artifact(case_id, artifact,
                                          artifact_media_type, actor)
            payload["artifact_id"] = aid
            payload["media_type"] = artifact_media_type
        ev = self._append(case_id, "evidence_added", actor, payload, orbit=orbit)
        for target in verifies or []:
            self.verify_evidence(case_id, target, actor, orbit=orbit)
        return ev

    def verify_evidence(self, case_id: str, evidence_id: str, verifier: str,
                        orbit: str = "system") -> dict:
        """Independent verification. A producer may never verify its own
        evidence; verification is an edge + event, so provenance survives."""
        facts = self.facts(case_id)
        node = facts.node(evidence_id)
        if not node or node.kind != "evidence":
            raise GateError(f"{evidence_id} is not evidence")
        producer = node.attrs.get("produced_by")
        if verifier == producer:
            raise AuthorityError(
                f"{verifier} produced {evidence_id}; critical evidence cannot be "
                f"approved by the process that produced it")
        return self._append(case_id, "edge_added", verifier, {
            "src_id": verifier, "rel": "VERIFIED_BY", "dst_id": evidence_id,
            "attrs": {"verified_at": _now()}}, orbit=orbit)

    # ------------------------------------------------------------ experiment
    def request_experiment(self, case_id: str, branch_id: str, experiment_id: str,
                           command: str, environment: str,
                           expected_observable: str, actor: str,
                           tests: list[str] | None = None,
                           controls: list[str] | None = None,
                           commit_sha: str | None = None,
                           orbit: str = "attack") -> dict:
        facts = self.facts(case_id)
        self._assert_not_sealed_output(facts, branch_id, actor)
        return self._append(case_id, "experiment_requested", actor, {
            "experiment_id": experiment_id, "branch_id": branch_id,
            "command": command, "environment": environment,
            "expected_observable": expected_observable,
            "tests": tests or [], "controls": controls or [],
            "commit_sha": commit_sha}, orbit=orbit)

    def complete_experiment(self, case_id: str, experiment_id: str, actor: str,
                            outcome: str, observed: str,
                            artifacts: list[bytes] | None = None,
                            exit_code: int | None = None,
                            orbit: str = "attack") -> dict:
        facts = self.facts(case_id)
        node = facts.node(experiment_id)
        if not node or node.kind != "experiment":
            raise GateError(f"{experiment_id} is not an experiment")
        self._assert_node_unsealed(facts, experiment_id, actor)
        if node.attrs.get("outcome") != "pending":
            raise GateError(f"{experiment_id} already completed; fork to re-run")
        hashes = []
        for blob in artifacts or []:
            hashes.append(self.store.put_artifact(case_id, blob,
                                                  "application/octet-stream", actor))
        return self._append(case_id, "experiment_completed", actor, {
            "experiment_id": experiment_id, "outcome": outcome,
            "observed": observed, "artifact_hashes": hashes,
            "exit_code": exit_code}, orbit=orbit)

    def complete_control(self, case_id: str, branch_id: str, control_id: str,
                         description: str, kind: str, result: str, actor: str,
                         tests: list[str] | None = None,
                         artifact: bytes | None = None,
                         orbit: str = "defense") -> dict:
        facts = self.facts(case_id)
        self._assert_not_sealed_output(facts, branch_id, actor)
        payload: dict[str, Any] = {
            "control_id": control_id, "branch_id": branch_id,
            "description": description, "kind": kind, "result": result,
            "tests": tests or []}
        if artifact is not None:
            payload["artifact_id"] = self.store.put_artifact(
                case_id, artifact, "text/plain", actor)
        return self._append(case_id, "control_completed", actor, payload,
                            orbit=orbit)

    # ----------------------------------------------------------------- gates
    def evaluate(self, case_id: str, branch_id: str) -> dict:
        facts = self.facts(case_id)
        results = {}
        for gate_id in GATE_CHAIN:
            res = evaluate_gate(facts, branch_id, gate_id)
            results[gate_id] = res.to_dict()
        return {"case_id": case_id, "branch_id": branch_id,
                "state": self._proof_state(facts, branch_id), "gates": results,
                "next_gate": next_gate(facts, branch_id)}

    def _proof_state(self, facts: Facts, branch_id: str) -> str:
        exps = facts.branch_nodes(branch_id, "experiment")
        passing = any(e.attrs.get("outcome") == "pass" for e in exps)
        gates = all(facts.gate_state(branch_id, g) == "PASSED" for g in GATE_CHAIN)
        stale = bool(facts.branch_state.get(branch_id, {}).get("stale_reason"))
        return derive_proof_state(proof_passing=passing, gates_passed=gates,
                                  stale=stale)

    def decide_gate(self, case_id: str, branch_id: str, gate_id: str, actor: str,
                    decision: str = "pass", note: str = "") -> dict:
        if gate_id not in GATE_CHAIN:
            raise GateError(f"unknown gate {gate_id!r}")
        facts = self.facts(case_id)
        branch = facts.node(branch_id)
        if not branch or branch.kind != "branch":
            raise GateError(f"unknown branch {branch_id!r}")
        lane = facts.branch_state.get(branch_id, {}).get("lane_status", "open")
        if lane in ("killed", "merged"):
            raise GateError(f"lane {branch_id} is {lane}; it cannot advance")

        if decision == "pass":
            result = evaluate_gate(facts, branch_id, gate_id)
            if result.state != "PASSED":
                # record the failed attempt; it is evidence, not an error to hide
                self._append(case_id, "gate_failed", actor, {
                    "branch_id": branch_id, "gate_id": gate_id,
                    "evaluation": result.to_dict(),
                    "note": note or "predicate unsatisfied"}, orbit="system")
                raise GateError(
                    f"gate {gate_id} predicate unsatisfied: "
                    f"{[c['check'] for c in result.failed]}")
            self._assert_approver_authority(facts, branch_id, gate_id, actor)
            return self._append(case_id, "gate_passed", actor, {
                "branch_id": branch_id, "gate_id": gate_id,
                "evaluation": result.to_dict(), "note": note}, orbit="system")
        return self._append(case_id, "gate_failed", actor, {
            "branch_id": branch_id, "gate_id": gate_id, "note": note,
            "evaluation": evaluate_gate(facts, branch_id, gate_id).to_dict()},
            orbit="system")

    def _assert_approver_authority(self, facts: Facts, branch_id: str,
                                   gate_id: str, actor: str) -> None:
        """Critical evidence cannot be approved by the process that produced it."""
        if gate_id not in CRITICAL_GATES:
            return
        producers = {n.attrs.get("produced_by")
                     for n in facts.branch_nodes(branch_id, "evidence")}
        producers |= {n.attrs.get("requested_by")
                      for n in facts.branch_nodes(branch_id, "experiment")}
        producers.discard(None)
        if actor in producers:
            raise AuthorityError(
                f"{actor} produced critical evidence for {gate_id} and may not "
                f"approve it (independent approver required)")
        sovereign = GATE_SOVEREIGN_ORBIT.get(gate_id)
        if sovereign and actor.endswith(f":{sovereign}"):
            producer_orbit = f"{branch_id}:{sovereign}"
            if producer_orbit in producers:
                raise AuthorityError(
                    f"gate {gate_id} may not be approved by its sovereign orbit")

    def approve_gate(self, case_id: str, branch_id: str, gate_id: str,
                     human: str, note: str = "") -> dict:
        auth = self.authority(human)
        if auth["kind"] != "human":
            raise AuthorityError(f"{human} is not a human approver")
        return self._append(case_id, "human_decision", human, {
            "decision": "approve_gate", "branch_id": branch_id,
            "gate_id": gate_id, "note": note}, orbit="system")

    # --------------------------------------------------------------- branches
    def fork_branch(self, case_id: str, parent_branch_id: str, branch_id: str,
                    actor: str, reason: str, at_gate: str | None = None,
                    orbit: str = "attack") -> dict:
        return self._append(case_id, "branch_forked", actor, {
            "parent_branch_id": parent_branch_id, "branch_id": branch_id,
            "reason": reason, "at_gate": at_gate}, orbit=orbit)

    def merge_branch(self, case_id: str, source_branch_id: str,
                     target_branch_id: str, actor: str,
                     resolution: dict | None = None) -> dict:
        return self._append(case_id, "branch_merged", actor, {
            "source_branch_id": source_branch_id,
            "target_branch_id": target_branch_id,
            "resolution": resolution or {}}, orbit="system")

    def park_branch(self, case_id: str, branch_id: str, actor: str,
                    reason: str) -> dict:
        return self._append(case_id, "branch_parked", actor, {
            "branch_id": branch_id, "reason": reason}, orbit="system")

    def mark_case_stale(self, case_id: str, reason: str, actor: str,
                        branch_id: str | None = None,
                        binding: str = "source") -> dict:
        """STALE: source, scope, environment, dependency or assumption changed."""
        facts = self.facts(case_id)
        blob = {"branch_id": branch_id or "*", "reason": reason,
                "binding": binding}
        res = self._append(case_id, "case_marked_stale", actor, blob, orbit="system")
        # Downgrade branch bindings: everything downstream of the changed
        # binding must be re-proven.
        if branch_id:
            bb = self.facts(case_id).branch_state.setdefault(branch_id, {})
            bb["stale_reason"] = reason
        return res

    def kill_branch(self, case_id: str, branch_id: str, actor: str, *,
                    suspected_mechanism: str, blocking_claim_id: str,
                    evidence_ids: list[str], invalidation_conditions: list[str],
                    verifier_id: str, repo_id: str | None = None,
                    commit_range: str | None = None) -> dict:
        facts = self.facts(case_id)
        nodes = facts.branch_nodes(branch_id)
        fp_comp = _fingerprint_from_nodes(nodes, suspected_mechanism)
        fp = compute_fingerprint(fp_comp)
        rec = {
            "kill_id": f"kill:{branch_id}:{len(facts.kills) + 1}",
            "suspected_mechanism": suspected_mechanism,
            "blocking_claim_id": blocking_claim_id,
            "evidence_ids": evidence_ids,
            "invalidation_conditions": invalidation_conditions,
            "author_id": actor, "verifier_id": verifier_id,
            "repo_id": repo_id, "commit_range": commit_range,
            "fingerprint": fp,
        }
        validate_kill_record(rec)
        payload = {**rec, "case_id": case_id, "branch_id": branch_id,
                   "components": fp_comp}
        self._append(case_id, "branch_killed", actor, {
            "branch_id": branch_id, "reason": suspected_mechanism},
            orbit="defense")
        return self._append(case_id, "kill_recorded", actor, payload,
                            orbit="defense")

    def challenge_kill(self, case_id: str, kill_id: str, actor: str, reason: str,
                       overriding_evidence: list[str]) -> dict:
        if not overriding_evidence:
            raise AuthorityError(
                "a kill may only be reopened with evidence addressing its "
                "invalidation conditions")
        return self._append(case_id, "kill_challenged", actor, {
            "kill_id": kill_id, "reason": reason,
            "overriding_evidence": overriding_evidence}, orbit="history")

    def kill_check(self, case_id: str, *, fingerprint_components: dict,
                   repo_id: str | None, commit_range: str | None,
                   offered_evidence: list[str]) -> KillCheck:
        facts = self.facts(case_id)
        fp = compute_fingerprint(fingerprint_components)
        return check_against_kills(facts.kills, fingerprint=fp, repo_id=repo_id,
                                   commit_range=commit_range,
                                   offered_evidence=offered_evidence)

    # ----------------------------------------------------------------- orbits
    def seal_orbit(self, case_id: str, orbit: str, actor: str) -> dict:
        if orbit not in ORBITS:
            raise GateError(f"unknown orbit {orbit!r}")
        facts = self.facts(case_id)
        if orbit in facts.seals:
            raise GateError(f"orbit {orbit} already sealed")
        node_ids = [n.node_id for n in facts.nodes.values() if n.orbit == orbit]
        blob = json.dumps({
            "orbit": orbit,
            "nodes": sorted((n.node_id, n.kind, n.label)
                            for n in facts.nodes.values() if n.orbit == orbit),
            "edges": sorted((e.src_id, e.rel, e.dst_id) for e in facts.live_edges()
                            if e.produced_by == actor or
                            (facts.node(e.src_id) and
                             facts.node(e.src_id).orbit == orbit)),
        }, sort_keys=True)
        import hashlib
        seal_hash = "sha256:" + hashlib.sha256(blob.encode()).hexdigest()
        edges = [e for e in facts.live_edges()
                 if facts.node(e.src_id) and facts.node(e.src_id).orbit == orbit]
        return self._append(case_id, "orbit_sealed", actor, {
            "orbit": orbit, "seal_hash": seal_hash, "node_ids": node_ids,
            "edge_count": len(edges)}, orbit=orbit)

    def merge_orbits(self, case_id: str, actor: str,
                     orbits: list[str] | None = None) -> dict:
        """Merge sealed orbit outputs, preserving agreement, contradiction,
        differing assumptions, differing source versions and open disputes."""
        orbits = orbits or ["attack", "defense"]
        facts = self.facts(case_id)
        missing = [o for o in orbits if o not in facts.seals]
        if missing:
            raise GateError(f"cannot merge unsealed orbits: {missing}")
        resolution = _compute_merge(facts, orbits)
        out = self._append(case_id, "orbit_merged", actor, {
            "orbit": "+".join(orbits), "orbits": orbits,
            "resolution": resolution}, orbit="system")
        return out

    # -------------------------------------------------------------- context
    def context_packet(self, case_id: str, *, role: str, agent_id: str,
                       branch_id: str, task: dict | None = None,
                       extra_anchors: list[str] | None = None,
                       use_summary_cache: bool = False,
                       stage: str | None = None) -> ContextPacket:
        facts = self.facts(case_id)
        summary = None
        if use_summary_cache:
            row = self.store.q1(
                "SELECT text, derived_from_seq FROM cw.summary_cache WHERE scope=%s",
                (branch_id,))
            if row and row["derived_from_seq"] == facts.upto_seq:
                summary = f"[DISPOSABLE CACHE — not evidence] {row['text']}"
        packet = cut_packet(facts, role=role, agent_id=agent_id,
                            branch_id=branch_id, task=task,
                            extra_anchors=extra_anchors or [],
                            summary_cache=summary, stage=stage)
        self.store.q(
            """INSERT INTO cw.context_packet (packet_id, case_id, agent_id, role,
                    node_ids, body, created_seq, cache_only)
               VALUES (%s,%s,%s,%s,%s,%s,%s,true) ON CONFLICT DO NOTHING""",
            (packet.packet_id, case_id, agent_id, role, packet.node_ids,
             _jsonb(packet.to_dict()), facts.upto_seq))
        return packet

    def cache_summary(self, case_id: str, scope: str, text: str) -> None:
        """Model-generated summaries are disposable caches. They are tagged and
        can never be cited: ``add_evidence`` rejects cache ids."""
        facts = self.facts(case_id)
        key = f"summary:{case_id}:{scope}:{facts.upto_seq}"
        self.store.q(
            """INSERT INTO cw.summary_cache (cache_key, scope, text,
                    derived_from_seq, disposable)
               VALUES (%s,%s,%s,%s,true) ON CONFLICT (cache_key) DO NOTHING""",
            (key, scope, text, facts.upto_seq))

    # --------------------------------------------------------------- novelty
    def fingerprint_branch(self, case_id: str, branch_id: str, actor: str,
                           sink: str, authority: str, transform: str = "",
                           precondition: str = "", target: str = "",
                           compare_against: str | None = None) -> dict:
        comp = components(sink=sink, authority=authority, transform=transform,
                          precondition=precondition, target=target)
        fp = compute_fingerprint(comp)
        comparison = None
        if compare_against:
            other = self.facts(case_id).node(compare_against)
            other_comp = other.attrs.get("components") if other else None
            if other_comp:
                comparison = compare(comp, other_comp)
        self._append(case_id, "precedent_abstracted", actor, {
            "precedent_id": fp, "kind": "vulnerability_pattern",
            "title": f"{sink} via {authority}",
            "fingerprint": fp, "components": comp,
            "source_case": case_id, "branch_id": branch_id},
            orbit="history")
        self._append(case_id, "edge_added", actor, {
            "src_id": fp, "rel": "ABSTRACTS_TO", "dst_id": branch_id,
            "attrs": {"components": comp, "computed": True}}, orbit="history")
        return {"fingerprint": fp, "components": comp,
                "comparison": comparison}

    # ---------------------------------------------------------------- impact
    def derive_impact(self, case_id: str, branch_id: str, impact_id: str,
                      summary: str, severity: str, actor: str,
                      about_claims: list[str], economics: dict | None = None,
                      orbit: str = "impact") -> dict:
        facts = self.facts(case_id)
        self._assert_not_sealed_output(facts, branch_id, actor)
        return self._append(case_id, "impact_derived", actor, {
            "impact_id": impact_id, "branch_id": branch_id, "summary": summary,
            "severity": severity, "about_claims": about_claims,
            "economics": economics or {}}, orbit=orbit)

    # -------------------------------------------------------------- reports
    def build_report(self, case_id: str, branch_id: str, actor: str) -> dict:
        from .report import build_report
        return build_report(self, case_id, branch_id, actor)

    def register_precedent(self, case_id: str, precedent_id: str, kind: str,
                           title: str, actor: str, body: dict | None = None,
                           fingerprint: str | None = None,
                           repo_id: str | None = None,
                           conditions: list[str] | None = None) -> dict:
        return self._append(case_id, "precedent_abstracted", actor, {
            "precedent_id": precedent_id, "kind": kind, "title": title,
            "body": body or {}, "fingerprint": fingerprint,
            "repo_id": repo_id, "conditions": conditions or [],
            "source_case": case_id}, orbit="history")

    def record_fix(self, case_id: str, fix_id: str, description: str, actor: str,
                   advisory: str | None = None, commit_sha: str | None = None,
                   repo_id: str | None = None,
                   fixes_claims: list[str] | None = None) -> dict:
        return self._append(case_id, "fix_recorded", actor, {
            "fix_id": fix_id, "description": description, "advisory": advisory,
            "commit_sha": commit_sha, "repo_id": repo_id,
            "fixes_claims": fixes_claims or []}, orbit="history")

    def human_decision(self, case_id: str, decision: str, actor: str,
                       branch_id: str | None = None, note: str = "") -> dict:
        if decision in ("submit_report", "contact_target"):
            raise AuthorityError(
                f"{decision} is not performable by the runtime: Clockwork prepares "
                f"packages for human submission and never contacts a target")
        return self._append(case_id, "human_decision", actor, {
            "decision": decision, "branch_id": branch_id, "note": note},
            orbit="system")


def _jsonb(obj: Any):
    import psycopg.types.json
    return psycopg.types.json.Jsonb(obj)


def _fingerprint_from_nodes(nodes: list[FactNode], mechanism: str) -> dict:
    text = " ".join([mechanism] + [n.label or "" for n in nodes]).lower()
    sink = "unknown"
    for token, canonical in (
            ("sqli", "sqli"), ("sql", "sqli"), ("ssrf", "ssrf"),
            ("rce", "rce"), ("command", "rce"), ("deserial", "rce"),
            ("xss", "xss"), ("auth", "authz"), ("idor", "authz"),
            ("access", "authz"), ("oracle", "oracle"), ("precision", "precision-loss"),
            ("round", "rounding"), ("race", "race"), ("reentr", "reentrancy"),
            ("replay", "replay"), ("xxe", "xxe"), ("traversal", "path-traversal")):
        if token in text:
            sink = canonical
            break
    authority = "attacker" if "attacker" in text else (
        "anonymous" if "anon" in text else "authenticated")
    return components(sink=sink, authority=authority,
                      transform="direct", precondition="none")


def _compute_merge(facts: Facts, orbits: list[str]) -> dict:
    """Preserve everything the orbits disagree about."""
    by_orbit = {o: [n for n in facts.nodes.values() if n.orbit == o]
                for o in orbits}
    claim_labels: dict[str, set[str]] = {}
    for orbit, nodes in by_orbit.items():
        for n in nodes:
            if n.kind == "claim":
                claim_labels.setdefault(n.label.strip().lower(), set()).add(orbit)
    agreement = [c for c, os_ in claim_labels.items() if len(os_) == len(orbits)]
    single_source = {c: sorted(os_) for c, os_ in claim_labels.items()
                     if len(os_) < len(orbits)}

    contradictions = []
    for e in facts.live_edges("CONTRADICTS"):
        s, d = facts.node(e.src_id), facts.node(e.dst_id)
        if s and d and s.orbit in orbits:
            contradictions.append({"evidence": e.src_id, "claim": e.dst_id,
                                   "by_orbit": s.orbit, "resolved": False})

    assumptions = [{"id": n.node_id, "statement": n.label, "orbit": n.orbit}
                   for n in facts.nodes.values() if n.kind == "assumption"]

    source_versions: dict[str, set[str]] = {}
    for n in facts.nodes.values():
        if n.commit_sha:
            source_versions.setdefault(n.branch_id or "case", set()).add(n.commit_sha)
    version_drift = {k: sorted(v) for k, v in source_versions.items()
                     if len(v) > 1}

    disputed = [c for c in contradictions if not c["resolved"]]
    return {
        "orbits": orbits,
        "agreement": sorted(agreement),
        "single_source_claims": single_source,
        "contradictions": contradictions,
        "unresolved_disputes": disputed,
        "assumptions": assumptions,
        "differing_assumptions": _differing_assumptions(assumptions, orbits),
        "source_version_drift": version_drift,
        "seals": {o: facts.seals[o]["seal_hash"] for o in orbits
                  if o in facts.seals},
    }


def _differing_assumptions(assumptions: list[dict], orbits: list[str]) -> list[dict]:
    """One entry per assumption that at least one participating orbit does not
    share, attributed to the orbits that do hold it."""
    seen: dict[str, set[str]] = {}
    for a in assumptions:
        seen.setdefault(a["statement"], set()).add(a["orbit"])
    out = []
    for stmt, holders in seen.items():
        if len(holders) < len(orbits):
            out.append({"statement": stmt, "only_in": sorted(holders)})
    return out
