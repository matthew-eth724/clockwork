"""Invariant tests for Clockwork Lite.

Each test proves a property the design claims, not a happy path:

* event log is append-only and hash-chained;
* decisions are a pure function of the log (projection is a cache);
* gates are ordered and machine-checked;
* critical evidence cannot be approved by its producer;
* orbits are blind until sealed, and merge preserves disagreement;
* context packets are strict subgraphs, not transcripts;
* kill memory blocks without suppressing, and expires with its commit range;
* novelty fingerprints are structural;
* reports refuse untraceable claims;
* placement is deterministic and replicated.
"""
from __future__ import annotations

import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from clockwork.constants import GATE_CHAIN  # noqa: E402
from clockwork.killmemory import (KillMemoryViolation,  # noqa: E402
                                  check_against_kills, commit_overlaps,
                                  validate_kill_record)
from clockwork.novelty import compare, components, compute_fingerprint  # noqa: E402
from clockwork.report import UntraceableClaim  # noqa: E402
from clockwork.runtime import (AuthorityError, GateError,  # noqa: E402
                               Runtime, _compute_merge)
from clockwork.shards import SHARD_COUNT, shard_for  # noqa: E402
from clockwork.store import Store  # noqa: E402


def _dsn() -> str:
    return os.environ.get(
        "CLOCKWORK_TEST_DSN",
        "postgresql://clockwork:clockwork@localhost:55432/clockwork")


@pytest.fixture()
def rt(tmp_path, monkeypatch):
    monkeypatch.setenv("CLOCKWORK_ARTIFACTS", str(tmp_path / "artifacts"))
    store = Store(_dsn())
    r = Runtime(store)
    r.boot()
    # Track every case this test creates so teardown can remove it. Tests must
    # not leave fixtures behind: this database may hold real investigations.
    created: list[str] = []
    _orig_open = r.open_case

    def _tracked_open(case_id, *a, **kw):
        created.append(case_id)
        return _orig_open(case_id, *a, **kw)

    r.open_case = _tracked_open  # type: ignore[method-assign]
    r._created_cases = created  # type: ignore[attr-defined]
    suffix = uuid.uuid4().hex[:8]
    r.register_agent("human:rev", "human", "reviewer", ["approve"])
    r.register_agent(f"atk-{suffix}", "agent", "attack",
                     ["produce_evidence", "run_experiment", "orbit:attack"])
    r.register_agent(f"def-{suffix}", "agent", "defense",
                     ["produce_evidence", "run_experiment", "orbit:defense"])
    r.register_agent(f"hist-{suffix}", "agent", "history",
                     ["produce_evidence", "orbit:history"])
    r.register_agent(f"imp-{suffix}", "agent", "impact",
                     ["produce_evidence", "orbit:impact"])
    r.suffix = suffix  # type: ignore[attr-defined]
    yield r
    _purge(r, created)
    r.close()


def _purge(rt, case_ids):
    """Remove test cases and their artefacts. Event rows are append-only and the
    trigger blocks DELETE, so they are removed with the trigger disabled inside a
    single transaction — the log is still never mutated in normal operation."""
    if not case_ids:
        return
    for cid in case_ids:
        try:
            rt.store.q("ALTER TABLE cw.case_event DISABLE TRIGGER ALL",
                       lock_caps=False)
            rt.store.q("DELETE FROM cw.case_event WHERE case_id=%s", (cid,),
                       lock_caps=False)
            rt.store.q("ALTER TABLE cw.case_event ENABLE TRIGGER ALL",
                       lock_caps=False)
            for table in ("edge", "node", "gate", "report_section",
                          "case_artifact_replica", "context_packet"):
                rt.store.q(f"DELETE FROM cw.{table} WHERE case_id=%s", (cid,),
                           lock_caps=False)
            rt.store.q("DELETE FROM cw.case WHERE case_id=%s", (cid,),
                       lock_caps=False)
        except Exception:  # noqa: BLE001 - cleanup must never fail a test
            pass


def _case(rt, prefix="T"):
    cid = f"{prefix}-{rt.suffix}-{uuid.uuid4().hex[:6]}"
    rt.open_case(cid, "test", ["repo"], {"repo_id": "repo",
                                         "commit_sha": "a" * 40}, "human:rev",
                 branches=[{"branch_id": "L1", "repo_id": "repo",
                            "commit_range": "a" * 40}])
    return cid


# --------------------------------------------------------------------- events
def test_event_log_is_append_only_and_hash_chained(rt):
    cid = _case(rt)
    ok, why = rt.store.verify_chain(cid)
    assert ok, why
    with pytest.raises(Exception):
        rt.store.q("UPDATE cw.case_event SET payload='{}' WHERE case_id=%s", (cid,))
    with pytest.raises(Exception):
        rt.store.q("DELETE FROM cw.case_event WHERE case_id=%s", (cid,))
    with pytest.raises(Exception):
        rt.store.q("TRUNCATE cw.case_event")


def test_tampered_event_breaks_chain_detection(rt):
    cid = _case(rt)
    rt.seed_candidate(cid, "L1", f"atk-{rt.suffix}", "x", "repo", "a" * 40)
    # bypass the trigger by dropping it and rewriting history directly
    rt.store.q("DROP TRIGGER IF EXISTS case_event_no_update ON cw.case_event")
    rt.store.q("ALTER TABLE cw.case_event DISABLE TRIGGER ALL")
    rt.store.q("UPDATE cw.case_event SET actor_id='ghost' "
               "WHERE case_id=%s AND seq=2", (cid,))
    rt.store.q("ALTER TABLE cw.case_event ENABLE TRIGGER ALL")
    ok, why = rt.store.verify_chain(cid)
    assert not ok and "hash mismatch" in why


def test_decisions_are_a_pure_function_of_the_log(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "ssrf", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "route is reachable", atk)
    rt.request_experiment(cid, "L1", "e1", "make repro", "local",
                          "200 with metadata body", atk, tests=["c1"],
                          commit_sha="a" * 40)
    rt.complete_experiment(cid, "e1", atk, "pass", "169.254.169.254 body")
    before = rt.evaluate(cid, "L1")
    # wipe every derived table; replay must reproduce identical decisions
    for table in ("node", "edge", "gate", "report_section"):
        rt.store.q(f"DELETE FROM cw.{table} WHERE case_id=%s", (cid,))
    rt._facts_cache.clear()
    after = rt.evaluate(cid, "L1")
    assert before == after


# ---------------------------------------------------------------------- gates
def test_gates_are_ordered_and_cannot_be_skipped(rt):
    cid = _case(rt)
    for gate in GATE_CHAIN[1:]:
        with pytest.raises(GateError):
            rt.decide_gate(cid, "L1", gate, "human:rev")
    assert rt.facts(cid).gate_state("L1", "local_proof") != "PASSED"


def test_gate_predicates_are_machine_readable(rt):
    cid = _case(rt)
    res = rt.evaluate(cid, "L1")
    every_leaf = set()
    for gate in GATE_CHAIN:
        assert res["gates"][gate]["checks"], gate
        for c in res["gates"][gate]["checks"]:
            every_leaf.add(c["check"])
    assert {"experiment_outcome", "control_result", "orbit_sealed",
            "human_approved", "independent_verifier"} <= every_leaf


# ------------------------------------------------------------------ authority
def test_producer_cannot_approve_its_own_critical_evidence(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.add_evidence(cid, "L1", "ev1", atk, kind="proof")
    with pytest.raises(AuthorityError):
        rt.verify_evidence(cid, "ev1", atk)


def test_no_agent_can_submit_or_contact_a_target(rt):
    cid = _case(rt)
    for decision in ("submit_report", "contact_target"):
        with pytest.raises(AuthorityError):
            rt.human_decision(cid, decision, "human:rev")


def test_capability_submission_is_not_grantable(rt):
    with pytest.raises(AuthorityError):
        rt.register_agent(f"rogue-{rt.suffix}", "agent", "rogue",
                          ["submit_report"])
    with pytest.raises(AuthorityError):
        rt.register_agent(f"rogue2-{rt.suffix}", "agent", "rogue",
                          ["expand_authority"])


def test_contradictory_evidence_cannot_be_deleted_only_ruled_out(rt):
    cid = _case(rt)
    atk, dfn = f"atk-{rt.suffix}", f"def-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "claim", atk)
    rt.add_evidence(cid, "L1", "ev-bad", dfn, kind="control",
                    contradicts=["c1"], orbit="defense")
    with pytest.raises(Exception):
        rt.store.q("UPDATE cw.case_event SET actor_id='x' WHERE case_id=%s", (cid,))
    rt.add_evidence(cid, "L1", "ev-ruledout", atk, kind="proof",
                    rules_out=["ev-bad"])
    edges = rt.facts(cid).live_edges("CONTRADICTS")
    assert edges, "contradiction must remain visible after being ruled out"


# --------------------------------------------------------------- blind orbits
def test_attack_output_is_structurally_absent_from_defense_packet(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "secret attack hypothesis", atk)
    rt.seal_orbit(cid, "attack", atk)
    atk_ids = {n.node_id for n in rt.facts(cid).nodes.values()
               if n.orbit == "attack" and n.kind != "branch"}
    pkt = rt.context_packet(cid, role="defense_orbit",
                            agent_id=f"def-{rt.suffix}", branch_id="L1")
    visible = {n["id"] for n in pkt.nodes}
    assert not (atk_ids & visible)
    assert pkt.withheld["blinded_orbit_nodes"]


def test_sealed_orbit_output_cannot_be_mutated(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.seal_orbit(cid, "attack", atk)
    # pre-seal lane: mutating sealed output is refused
    with pytest.raises(AuthorityError):
        rt.propose_claim(cid, "L1", "late", "after the seal", atk)
    # the same activity may continue on a lane created after the seal
    rt.seed_candidate(cid, "L2", atk, "new hypothesis", "repo", "a" * 40)
    rt.propose_claim(cid, "L2", "c-next", "continuation", atk)


def test_merge_preserves_disagreement_and_assumption_drift(rt):
    cid = _case(rt)
    atk, dfn = f"atk-{rt.suffix}", f"def-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c-atk", "sink is reachable", atk)
    rt.declare_assumption(cid, "L1", "a-atk", "edge cache is absent", atk,
                          falsifiable_by=["cache dump"])
    rt.add_evidence(cid, "L1", "ev-def", dfn, kind="control",
                    contradicts=["c-atk"], orbit="defense")
    rt.declare_assumption(cid, "L1", "a-def", "cache key includes tenant", dfn,
                          falsifiable_by=["key dump"], orbit="defense")
    rt.seal_orbit(cid, "attack", atk)
    rt.seal_orbit(cid, "defense", dfn)
    with pytest.raises(GateError):
        rt.merge_orbits(cid, "human:rev", ["attack", "history"])  # unsealed
    rt.merge_orbits(cid, "human:rev", ["attack", "defense"])
    res = rt.facts(cid).merges[-1]["resolution"]
    assert res["contradictions"], "contradiction must be preserved"
    assert res["unresolved_disputes"], "unresolved dispute must be preserved"
    assert res["differing_assumptions"], "assumption drift must be preserved"
    assert len(res["seals"]) == 2


# ------------------------------------------------------------- context packets
def test_packet_is_a_strict_subgraph_not_a_transcript(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    for i in range(40):
        rt.add_evidence(cid, "L1", f"ev{i}", atk, kind="metadata",
                        commit_sha="a" * 40, source_ref=f"f{i}:1")
    pkt = rt.context_packet(cid, role="attack_orbit", agent_id=atk,
                            branch_id="L1")
    assert pkt.stats["nodes"] < pkt.stats["full_case_nodes"]
    assert "transcript" not in pkt.to_dict()
    assert pkt.to_dict()["canonical"] is False


def test_summaries_are_disposable_and_never_canonical(rt):
    cid = _case(rt)
    rt.cache_summary(cid, "L1", "a model wrote this")
    pkt = rt.context_packet(cid, role="attack_orbit",
                            agent_id=f"atk-{rt.suffix}", branch_id="L1",
                            use_summary_cache=True)
    assert pkt.disposable_summary.startswith("[DISPOSABLE CACHE")
    # a summary id can never be attached as evidence
    with pytest.raises(GateError):
        rt.support_claim(cid, "nonexistent", ["summary:whatever"],
                         f"atk-{rt.suffix}")


# --------------------------------------------------------------- kill memory
def test_kill_record_requires_independent_verifier_and_conditions(rt):
    with pytest.raises(KillMemoryViolation):
        validate_kill_record({"kill_id": "k", "suspected_mechanism": "m",
                              "blocking_claim_id": "c", "evidence_ids": ["e"],
                              "invalidation_conditions": ["x"],
                              "author_id": "same", "verifier_id": "same"})
    with pytest.raises(KillMemoryViolation):
        validate_kill_record({"kill_id": "k", "suspected_mechanism": "m",
                              "blocking_claim_id": "c", "evidence_ids": ["e"],
                              "invalidation_conditions": [],
                              "author_id": "a", "verifier_id": "b"})


def test_kill_blocks_new_lane_without_new_evidence_but_never_suppresses(rt):
    cid = _case(rt)
    atk, dfn = f"atk-{rt.suffix}", f"def-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "sqli in search", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c-block", "query is parameterised", atk)
    rt.add_evidence(cid, "L1", "ev-block", dfn, kind="control",
                    rules_out=["c-block"], orbit="defense")
    kill = rt.kill_branch(
        cid, "L1", dfn, suspected_mechanism="sqli in search",
        blocking_claim_id="c-block", evidence_ids=["ev-block"],
        invalidation_conditions=["ORM raw fragment reintroduced"],
        verifier_id="human:rev", repo_id="repo", commit_range="a" * 40)
    rec = rt.facts(cid).kills[kill["payload"]["kill_id"]]

    chk = rt.kill_check(cid, fingerprint_components=rec["components"],
                        repo_id="repo", commit_range="a" * 40,
                        offered_evidence=[])
    assert chk.blocked and chk.must_evidence == ["ORM raw fragment reintroduced"]

    reopened = rt.kill_check(cid, fingerprint_components=rec["components"],
                             repo_id="repo", commit_range="a" * 40,
                             offered_evidence=["ORM raw fragment reintroduced"])
    assert not reopened.blocked

    moved = rt.kill_check(cid, fingerprint_components=rec["components"],
                          repo_id="repo", commit_range="b" * 40,
                          offered_evidence=[])
    assert not moved.blocked, "a kill is bound to the commit range it covered"


def test_challenging_a_kill_requires_evidence(rt):
    cid = _case(rt)
    with pytest.raises(AuthorityError):
        rt.challenge_kill(cid, "kill:whatever", "human:rev", "feels wrong", [])


def test_commit_range_overlap_semantics():
    assert commit_overlaps(None, "a" * 40)
    assert commit_overlaps("abc..def", "abc..def")
    assert not commit_overlaps("aaa..bbb", "ccc..ddd")


# ----------------------------------------------------------------- novelty
def test_fingerprints_are_structural_not_textual():
    a = components(sink="sql-injection", authority="authenticated",
                   transform="direct", precondition="tenant-admin")
    b = components(sink="sqli", authority="authenticated",
                   transform="direct", precondition="tenant-admin")
    assert compute_fingerprint(a) == compute_fingerprint(b)
    c = components(sink="sqli", authority="authenticated", transform="direct",
                   precondition="anonymous")
    assert compute_fingerprint(a) != compute_fingerprint(c)
    res = compare(a, c)
    assert res["duplicate_likely"] is False
    assert "precondition" in res["distinguishing_components"]


# ------------------------------------------------------------------ reports
def test_report_refuses_untraceable_claims(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c-unsupported", "a very attractive claim", atk)
    with pytest.raises(UntraceableClaim):
        rt.build_report(cid, "L1", "human:rev")


def test_report_traces_claim_to_artifact_and_never_autosubmits(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "tenant boundary is crossed", atk)
    rt.request_experiment(cid, "L1", "e1", "make repro", "local env",
                          "403", atk, tests=["c1"], commit_sha="a" * 40,
                          controls=["ctl1"])
    rt.complete_experiment(cid, "e1", atk, "pass", "200 other tenant",
                           artifacts=[b"proof"])
    rt.add_evidence(cid, "L1", "ev1", atk, kind="proof", supports=["c1"],
                    commit_sha="a" * 40, source_ref="app/x.py:1",
                    artifact=b"200 other tenant")
    rt.verify_evidence(cid, "ev1", "human:rev")
    pkg = rt.build_report(cid, "L1", "human:rev")
    assert pkg["qc"]["auto_submit"] is False
    assert pkg["qc"]["human_submission_required"] is True
    prov = next(s for s in pkg["sections"] if s["section_id"] == "sec:provenance")
    trace = prov["provenance"]["traces"][0]
    ev = trace["evidence"][0]
    assert ev["experiments"][0]["command"] == "make repro"
    assert ev["artifacts"]
    assert ev["independent_verification"] is True
    assert "make repro" in pkg["markdown"]


# -------------------------------------------------------------- staleness
def test_stale_marks_branch_and_downgrades_proof_state(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.request_experiment(cid, "L1", "e1", "make repro", "local", "200",
                          atk, commit_sha="a" * 40, controls=["c"],
                          tests=["c1"])
    rt.complete_experiment(cid, "e1", atk, "pass", "200", artifacts=[b"x"])
    assert rt.evaluate(cid, "L1")["state"] in ("RED", "YELLOW")
    rt.mark_case_stale(cid, "dependency bumped", "human:rev", branch_id="L1")
    assert rt.evaluate(cid, "L1")["state"] == "STALE"


# --------------------------------------------------------------- placement
def test_shard_assignment_is_stable_and_bounded():
    ids = [f"CASE-{i}" for i in range(500)]
    shards = {shard_for(i) for i in ids}
    assert all(0 <= s < SHARD_COUNT for s in shards)
    assert shard_for("CASE-42") == shard_for("CASE-42")
    assert len(shards) > 40


def test_placement_replicates_and_gates_worker_eligibility(rt):
    cid = _case(rt)
    pl = rt.placement(cid)
    assert {r["role"] for r in pl["replicas"]} == {"primary", "replica"}
    sched = rt.schedule(cid, "L1", {"repos": ["other-repo"]})
    assert sched["eligible"] is False
    sched_ok = rt.schedule(cid, "L1", {"repos": ["repo"]})
    assert sched_ok["eligible"] is True
    assert sched_ok["next_gate"] == "scope_admission"


# ------------------------------------------------- declared-then-seeded lanes
def test_lane_declared_before_seal_but_seeded_after_is_a_fresh_hypothesis(rt):
    """Declaration is bookkeeping; seeding is the investigative act."""
    cid = _case(rt)                      # L1 declared inside case_opened
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "first hypothesis", "repo", "a" * 40)
    rt.seal_orbit(cid, "attack", atk)
    with pytest.raises(AuthorityError):
        rt.propose_claim(cid, "L1", "c-late", "mutates sealed output", atk)
    # a lane declared at open but seeded after the seal is new work
    rt.seed_candidate(cid, "L1", atk, "second hypothesis", "repo", "a" * 40)
    assert rt.facts(cid).node("L1").attrs.get("seeded_seq")


def test_seeded_hypothesis_reaches_the_generated_report_summary(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "ssrf into metadata service", "repo",
                      "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "fetcher honours user URLs", atk)
    rt.request_experiment(cid, "L1", "e1", "make repro", "local", "200", atk,
                          tests=["c1"], commit_sha="a" * 40, controls=["ctl"])
    rt.complete_experiment(cid, "e1", atk, "pass", "200", artifacts=[b"x"])
    rt.add_evidence(cid, "L1", "ev1", atk, kind="proof", supports=["c1"],
                    artifact=b"x")
    pkg = rt.build_report(cid, "L1", "human:rev")
    summary = next(sec for sec in pkg["sections"]
                   if sec["section_id"] == "sec:summary")
    assert "ssrf into metadata service" in summary["body"]


# ------------------------------------------- documented support path must work
def test_support_claim_creates_supports_edge_and_backs_the_claim(rt):
    """The documented way to attach evidence to a claim must actually link it.

    Regression: support_claim() appended a claim_supported event that the
    projection ignored, so the call succeeded, the log grew, and the claim stayed
    unsupported. Callers got no error and the gate failed anyway.
    """
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "the claim", atk)
    rt.add_evidence(cid, "L1", "ev1", atk, kind="proof", commit_sha="a" * 40)

    rt.support_claim(cid, "c1", ["ev1"], atk)

    facts = rt.facts(cid)
    edges = [(e.src_id, e.dst_id) for e in facts.edges_to("c1", "SUPPORTS")]
    assert ("ev1", "c1") in edges, "support_claim did not create a SUPPORTS edge"
    assert facts.node("c1").attrs.get("status") == "supported"


def test_support_claim_satisfies_the_gate_that_requires_a_supports_edge(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "reachable", atk)
    rt.add_evidence(cid, "L1", "ev-route", atk, kind="metadata",
                    commit_sha="a" * 40, source_ref="app/routes.py:1")
    rt.support_claim(cid, "c1", ["ev-route"], atk)
    ev = rt.evaluate(cid, "L1")
    checks = ev["gates"]["reachability"]["checks"]
    support = [c for c in checks if c["check"] == "edge_exists"]
    assert support and support[0]["ok"], support


def test_support_claim_rejects_non_evidence_and_unknown_targets(rt):
    cid = _case(rt)
    atk = f"atk-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "c", atk)
    rt.add_evidence(cid, "L1", "ev1", atk, kind="proof")
    with pytest.raises(GateError):
        rt.support_claim(cid, "c1", ["nope"], atk)
    with pytest.raises(GateError):
        rt.support_claim(cid, "claim-that-does-not-exist", ["ev1"], atk)


def test_contradict_claim_creates_contradicts_edge(rt):
    """Same class of bug: contradict_claim must also leave a visible edge."""
    cid = _case(rt)
    atk, dfn = f"atk-{rt.suffix}", f"def-{rt.suffix}"
    rt.seed_candidate(cid, "L1", atk, "x", "repo", "a" * 40)
    rt.propose_claim(cid, "L1", "c1", "c", atk)
    rt.add_evidence(cid, "L1", "ev-def", dfn, kind="control", orbit="defense")
    rt.contradict_claim(cid, "c1", ["ev-def"], dfn)
    facts = rt.facts(cid)
    assert ("ev-def", "c1") in [(e.src_id, e.dst_id)
                                for e in facts.edges_to("c1", "CONTRADICTS")]
