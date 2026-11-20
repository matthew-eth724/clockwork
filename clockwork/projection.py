"""Event -> fact projection.

The event log is canonical; this module is the *only* sanctioned way to derive
state from it. Everything downstream (gates, context packets, reports, UI)
consumes ``Facts``.
"""
from __future__ import annotations

from typing import Any

from .constants import GATE_CHAIN
from .facts import FactEdge, FactNode, Facts

VALID_RELATIONS = {
    "SUPPORTS", "CONTRADICTS", "DEPENDS_ON", "TESTS", "RULES_OUT", "GENERATED_BY",
    "VERIFIED_BY", "BLOCKED_BY", "INVALIDATED_BY", "APPLIES_TO_COMMIT",
    "ABSTRACTS_TO", "DUPLICATE_OF", "FIXED_BY", "INCLUDED_IN",
}


def _node_from(node_id: str, kind: str, label: str, seq: int, ev: dict,
               **kw) -> FactNode:
    return FactNode(node_id=node_id, kind=kind, label=label, seq=seq,
                    branch_id=kw.get("branch_id", ev["payload"].get("branch_id")),
                    orbit=kw.get("orbit", ev.get("orbit", "system")),
                    attrs=kw.get("attrs", {}),
                    commit_sha=kw.get("commit_sha"),
                    source_ref=kw.get("source_ref"),
                    content_hash=kw.get("content_hash"),
                    sealed_seq=kw.get("sealed_seq"))


def project(events: list[dict]) -> Facts:
    """Replay append-only events into a fact set."""
    if not events:
        return Facts(case_id="", upto_seq=0)
    case_id = events[0]["case_id"]
    facts = Facts(case_id=case_id, upto_seq=events[-1]["seq"])
    # Agent identity is global (registered on the synthetic system case); hydrate
    # the authority view from every registration seen in the replay, plus the
    # human decisions made in this case.
    case_payload = next((e["payload"] for e in events
                         if e["event_type"] == "case_opened"), {})
    CASE = case_payload.get("case_id") or case_id

    for ev in events:
        seq = ev["seq"]
        et = ev["event_type"]
        p: dict[str, Any] = ev["payload"]
        orbit = ev.get("orbit") or "system"
        actor = ev["actor_id"]

        def add(node: FactNode) -> None:
            existing = facts.nodes.get(node.node_id)
            if existing is not None and existing.kind == node.kind:
                # a later event may enrich a pre-declared node (a lane declared
                # at case open is *seeded* later): merge attrs, keep first seq
                merged = {**existing.attrs, **{k: v for k, v in node.attrs.items()}}
                object.__setattr__(existing, "attrs", merged)
                object.__setattr__(existing, "label", node.label or existing.label)
                if node.orbit != "system":
                    object.__setattr__(existing, "orbit", node.orbit)
                for field_name in ("branch_id", "commit_sha", "source_ref"):
                    if getattr(node, field_name):
                        object.__setattr__(existing, field_name,
                                           getattr(node, field_name))
                facts.nodes[node.node_id] = existing
                return
            # older records may lack an explicit orbit; fall back to the
            # activity's orbit rather than silently defaulting to system
            if node.orbit == "system" and orbit != "system":
                node = FactNode(
                    node_id=node.node_id, kind=node.kind, label=node.label,
                    seq=node.seq, branch_id=node.branch_id, orbit=orbit,
                    status=node.status, attrs=node.attrs,
                    commit_sha=node.commit_sha, source_ref=node.source_ref,
                    content_hash=node.content_hash, sealed_seq=node.sealed_seq)
            if existing is not None and node.orbit == "system":
                # system-derived nodes (commits, artifacts created as a side
                # effect) inherit the orbit of the activity that first created
                # them, so an orbit's seal covers them too
                object.__setattr__(node, "orbit", existing.orbit)
            facts.nodes[node.node_id] = node

        def edge(src, rel, dst, attrs=None, produced_by=None, retired_seq=None):
            if rel not in VALID_RELATIONS:
                raise ValueError(f"unknown relationship {rel!r}")
            facts.edges.append(FactEdge(src_id=src, rel=rel, dst_id=dst, seq=seq,
                                        produced_by=produced_by or actor,
                                        attrs=attrs or {},
                                        retired_seq=retired_seq))

        if et == "case_opened":
            add(_node_from(p["case_id"], "case", p.get("title", p["case_id"]), seq,
                           ev, attrs={"repos": p.get("repos", []),
                                      "shard": p.get("shard")}))
            for b in p.get("branches", []):
                add(FactNode(node_id=b["branch_id"], kind="branch",
                             label=b.get("label", b["branch_id"]), seq=seq,
                             branch_id=b["branch_id"], orbit="system",
                             attrs={"commit_range": b.get("commit_range"),
                                    "repo_id": b.get("repo_id")}))
                edge(b["branch_id"], "INCLUDED_IN", CASE)

        elif et == "candidate_seeded":
            nid = p["branch_id"]
            add(FactNode(node_id=nid, kind="branch", label=p.get("label", nid),
                         seq=seq, branch_id=nid,
                         orbit=p.get("orbit") or orbit,
                         attrs={"repo_id": p.get("repo_id"),
                                "commit_range": p.get("commit_range"),
                                "seeded_by": actor,
                                "seeded_seq": seq,
                                "suspected_mechanism":
                                    p.get("suspected_mechanism", "")}))
            edge(nid, "INCLUDED_IN", CASE)

        elif et == "claim_proposed":
            nid = p["claim_id"]
            add(FactNode(node_id=nid, kind="claim", label=p["statement"], seq=seq,
                         branch_id=p.get("branch_id"),
                         orbit=p.get("orbit", orbit),
                         attrs={"claim_class": p.get("claim_class", "substantive"),
                                "produced_by": actor,
                                "confidence": p.get("confidence", 0.5),
                                "proposed_by": actor,
                                "verifier_required": p.get("verifier_required", False)}))
            for dep in p.get("depends_on", []):
                edge(nid, "DEPENDS_ON", dep)

        elif et == "assumption_declared":
            nid = p["assumption_id"]
            add(FactNode(node_id=nid, kind="assumption", label=p["statement"],
                         seq=seq, branch_id=p.get("branch_id"), orbit=orbit,
                         attrs={"falsifiable_by": p.get("falsifiable_by", []),
                                "author": actor}))
            for c in p.get("challenges_claims", []):
                edge(nid, "DEPENDS_ON", c)

        elif et == "evidence_added":
            nid = p["evidence_id"]
            add(FactNode(node_id=nid, kind="evidence", label=p.get("label", nid),
                         seq=seq, branch_id=p.get("branch_id"), orbit=orbit,
                         attrs={"evidence_kind": p.get("kind", "metadata"),
                                "produced_by": actor,
                                "independent": False,
                                "verified_by": [],
                                "experiment_id": p.get("experiment_id"),
                                # an evidence item is traceable to the
                                # experiments that bear on the claims it
                                # supports; record them structurally
                                "tested_by": [e.src_id for e in facts.edges
                                              if e.rel == "TESTS"
                                              and e.dst_id in (p.get("supports")
                                                               or [])],
                                "artifact_id": p.get("artifact_id")},
                         commit_sha=p.get("commit_sha"),
                         source_ref=p.get("source_ref"),
                         content_hash=p.get("artifact_id")))
            for c in p.get("supports", []):
                edge(nid, "SUPPORTS", c)
            for c in p.get("contradicts", []):
                edge(nid, "CONTRADICTS", c)
            for c in p.get("rules_out", []):
                edge(nid, "RULES_OUT", c)
            if p.get("commit_sha"):
                cid = f"commit:{p['commit_sha']}"
                if cid not in facts.nodes:
                    add(FactNode(node_id=cid, kind="commit", label=p["commit_sha"],
                                 seq=seq, commit_sha=p["commit_sha"],
                                 attrs={"repo_id": p.get("repo_id")}))
                edge(nid, "APPLIES_TO_COMMIT", cid)
            if p.get("artifact_id"):
                aid = p["artifact_id"]
                if aid not in facts.nodes:
                    add(FactNode(node_id=aid, kind="artifact", label=aid[7:19],
                                 seq=seq, content_hash=aid,
                                 attrs={"media_type": p.get("media_type", "text/plain"),
                                        "produced_by": actor,
                                        "storage_path": p.get("storage_path")}))
                edge(aid, "GENERATED_BY", nid)
            if p.get("experiment_id"):
                edge(p["experiment_id"], "TESTS", nid)

        elif et in ("claim_supported", "claim_contradicted"):
            # Attaching evidence to a claim must leave a visible edge and move
            # the claim's status. Appending the event alone is not enough: the
            # graph is what gates read, so an unprojected event is a silent
            # no-op that still looks like success to the caller.
            cid = p["claim_id"]
            rel = "SUPPORTS" if et == "claim_supported" else "CONTRADICTS"
            for eid in p.get("evidence_ids", []):
                edge(eid, rel, cid, {"via": et})
            claim = facts.nodes.get(cid)
            if claim is not None:
                supplied = list(p.get("evidence_ids", []))
                if et == "claim_supported":
                    cur = list(claim.attrs.get("supported_ev") or [])
                    for eid in supplied:
                        if eid not in cur:
                            cur.append(eid)
                    attrs = {**claim.attrs, "supported_ev": cur,
                             "status": "supported"}
                else:
                    cur = list(claim.attrs.get("contradicted_ev") or [])
                    for eid in supplied:
                        if eid not in cur:
                            cur.append(eid)
                    attrs = {**claim.attrs, "contradicted_ev": cur,
                             "status": "contradicted"}
                object.__setattr__(claim, "attrs", attrs)
                object.__setattr__(claim, "status", attrs["status"])

        elif et == "experiment_requested":
            nid = p["experiment_id"]
            add(FactNode(node_id=nid, kind="experiment", label=p["command"], seq=seq,
                         branch_id=p.get("branch_id"), orbit=orbit,
                         attrs={"command": p["command"],
                                "environment": p.get("environment", ""),
                                "expected_observable": p.get("expected_observable", ""),
                                "controls": p.get("controls", []),
                                "outcome": "pending",
                                "artifact_hashes": [],
                                "requested_by": actor,
                                "executed_by": None,
                                "commit_sha": p.get("commit_sha")},
                         commit_sha=p.get("commit_sha")))
            for c in p.get("tests", []):
                edge(nid, "TESTS", c)
            if p.get("commit_sha"):
                cid = f"commit:{p['commit_sha']}"
                if cid not in facts.nodes:
                    add(FactNode(node_id=cid, kind="commit", label=p["commit_sha"],
                                 seq=seq, commit_sha=p["commit_sha"]))
                edge(nid, "APPLIES_TO_COMMIT", cid)

        elif et == "experiment_completed":
            nid = p["experiment_id"]
            old = facts.nodes.get(nid)
            attrs = dict(old.attrs) if old else {}
            attrs.update({"outcome": p.get("outcome", "error"),
                          "observed": p.get("observed", ""),
                          "artifact_hashes": p.get("artifact_hashes", []),
                          "executed_by": actor,
                          "exit_code": p.get("exit_code")})
            add(FactNode(node_id=nid, kind="experiment",
                         label=old.label if old else nid, seq=seq,
                         branch_id=old.branch_id if old else p.get("branch_id"),
                         orbit=old.orbit if old else orbit, attrs=attrs,
                         commit_sha=old.commit_sha if old else p.get("commit_sha")))

        elif et == "control_completed":
            nid = p["control_id"]
            add(FactNode(node_id=nid, kind="control", label=p.get("description", nid),
                         seq=seq, branch_id=p.get("branch_id"), orbit=orbit,
                         attrs={"control_kind": p.get("kind", "decoy"),
                                "result": p.get("result", "pending"),
                                "produced_by": actor,
                                "artifact_id": p.get("artifact_id")}))
            for t in p.get("tests", []):
                edge(nid, "TESTS", t)
            if p.get("artifact_id"):
                aid = p["artifact_id"]
                if aid not in facts.nodes:
                    add(FactNode(node_id=aid, kind="artifact", label=aid[7:19],
                                 seq=seq, content_hash=aid,
                                 attrs={"produced_by": actor,
                                        "media_type": "text/plain"}))
                edge(aid, "GENERATED_BY", nid)

        elif et == "gate_passed":
            facts.gate_decisions[(p["branch_id"], p["gate_id"])] = {
                "state": "PASSED", "seq": seq, "decided_by": actor,
                "evaluation": p.get("evaluation", {}), "note": p.get("note")}

        elif et == "gate_failed":
            facts.gate_decisions[(p["branch_id"], p["gate_id"])] = {
                "state": "FAILED", "seq": seq, "decided_by": actor,
                "evaluation": p.get("evaluation", {}), "note": p.get("note")}

        elif et == "branch_forked":
            parent = p["parent_branch_id"]
            child = p["branch_id"]
            add(FactNode(node_id=child, kind="branch", label=p.get("label", child),
                         seq=seq, branch_id=child, orbit=orbit,
                         attrs={"parent": parent,
                                "fork_reason": p.get("reason", ""),
                                "forked_at_gate": p.get("at_gate")}))
            edge(child, "DEPENDS_ON", parent, {"kind": "fork"})

        elif et == "branch_merged":
            src, dst = p["source_branch_id"], p["target_branch_id"]
            facts.branch_state.setdefault(src, {})["lane_status"] = "merged"
            facts.branch_state.setdefault(src, {})["merged_into"] = dst
            edge(src, "DEPENDS_ON", dst, {"kind": "merge"})

        elif et == "branch_killed":
            b = p["branch_id"]
            facts.branch_state.setdefault(b, {})["lane_status"] = "killed"
            facts.branch_state.setdefault(b, {})["kill_reason"] = p.get("reason")

        elif et == "branch_parked":
            b = p["branch_id"]
            facts.branch_state.setdefault(b, {})["lane_status"] = "parked"

        elif et == "case_marked_stale":
            facts.branch_state.setdefault(p.get("branch_id", "*"), {})[
                "stale_reason"] = p.get("reason", "unspecified")
            facts.branch_state.setdefault(p.get("branch_id", "*"), {})[
                "stale_seq"] = seq

        elif et == "edge_added":
            edge(p["src_id"], p["rel"], p["dst_id"], p.get("attrs"),
                 produced_by=actor)
            if (p["rel"] == "ABSTRACTS_TO" and p["src_id"] in facts.nodes
                    and facts.nodes[p["src_id"]].kind == "fingerprint"
                    and facts.nodes[p["src_id"]].branch_id is None):
                fp = facts.nodes[p["src_id"]]
                object.__setattr__(fp, "branch_id", p["dst_id"])
            if p["rel"] == "VERIFIED_BY":
                target = facts.nodes.get(p["dst_id"])
                if target is not None:
                    vb = list(target.attrs.get("verified_by") or [])
                    if p["src_id"] not in vb:
                        vb.append(p["src_id"])
                    object.__setattr__(target, "attrs",
                                       {**target.attrs, "verified_by": vb})

        elif et == "edge_retired":
            for e in facts.edges:
                if (e.src_id == p["src_id"] and e.rel == p["rel"]
                        and e.dst_id == p["dst_id"] and e.retired_seq is None):
                    object.__setattr__(e, "retired_seq", seq)
                    break

        elif et == "orbit_sealed":
            facts.seals[p["orbit"]] = {"sealed_seq": seq,
                                       "seal_hash": p.get("seal_hash"),
                                       "node_ids": p.get("node_ids", []),
                                       "edge_count": p.get("edge_count", 0)}
            for nid in p.get("node_ids", []):
                n = facts.nodes.get(nid)
                if not n:
                    continue
                object.__setattr__(n, "sealed_seq", seq)
                object.__setattr__(n, "attrs", {**n.attrs, "sealed_seq": seq})
            facts.seals[p["orbit"]].setdefault("seq", seq)

        elif et == "orbit_merged":
            facts.merges.append({"orbit": p["orbit"],
                                 "orbits": p.get("orbits") or p["orbit"].split("+"),
                                 "seq": seq,
                                 "resolution": p.get("resolution", {})})

        elif et == "kill_recorded":
            facts.kills[p["kill_id"]] = {**p, "seq": seq, "author_id": actor,
                                          "verified": False}
            for eid in p.get("evidence_ids", []):
                if eid in facts.nodes:
                    edge(p["blocking_claim_id"], "BLOCKED_BY", eid,
                         {"kill_id": p["kill_id"]})

        elif et == "kill_challenged":
            k = facts.kills.get(p["kill_id"])
            if k:
                k["challenged_by"] = p.get("reason")
                k["challenge_seq"] = seq
                k["invalidated_by"] = p.get("overriding_evidence", [])
                for eid in p.get("overriding_evidence", []):
                    edge(eid, "INVALIDATED_BY", p["kill_id"], {"scope": "kill"})

        elif et == "human_decision":
            facts.human_decisions.append({**p, "seq": seq, "actor": actor,
                                          "orbit": orbit})
            facts.authority.setdefault(actor, {"kind": "human", "caps": set(),
                                               "seq": seq})

        elif et == "agent_registered":
            facts.authority[p["agent_id"]] = {
                "kind": p.get("kind", "agent"),
                "caps": set(p.get("caps", [])),
                "seq": seq}

        elif et == "scope_snapshot_captured":
            nid = p["scope_snapshot_id"]
            add(FactNode(node_id=nid, kind="scope_snapshot",
                         label=f"{p['repo_id']}@{p['commit_sha'][:8]}", seq=seq,
                         orbit=orbit, commit_sha=p["commit_sha"],
                         attrs={"repo_id": p["repo_id"],
                                "manifest": p.get("manifest", {})}))

        elif et == "impact_derived":
            nid = p["impact_id"]
            add(FactNode(node_id=nid, kind="impact", label=p["summary"], seq=seq,
                         branch_id=p.get("branch_id"), orbit=orbit,
                         attrs={"severity": p.get("severity"),
                                "economics": p.get("economics", {}),
                                "derived_by": actor}))
            for c in p.get("about_claims", []):
                edge(nid, "DEPENDS_ON", c)

        elif et == "fix_recorded":
            nid = p["fix_id"]
            add(FactNode(node_id=nid, kind="fix", label=p.get("description", nid),
                         seq=seq, orbit=orbit,
                         attrs={"repo_id": p.get("repo_id"),
                                "advisory": p.get("advisory"),
                                "commit_sha": p.get("commit_sha")},
                         commit_sha=p.get("commit_sha")))
            for c in p.get("fixes_claims", []):
                edge(nid, "FIXED_BY", c)   # FIXED_BY: claim is fixed by this fix

        elif et == "report_section_generated":
            facts.report_sections.append({**p, "seq": seq,
                                          "generated_by": actor})

        elif et == "artifact_stored":
            aid = p["artifact_id"]
            add(FactNode(node_id=aid, kind="artifact", label=aid[7:19], seq=seq,
                         content_hash=aid,
                         attrs={"media_type": p.get("media_type"),
                                "bytes": p.get("bytes"),
                                "storage_path": p.get("storage_path"),
                                "produced_by": actor}))

        elif et == "precedent_abstracted":
            facts.precedents[p["precedent_id"]] = {**p, "seq": seq,
                                                   "created_by": actor}
            if p.get("kind") == "vulnerability_pattern" and p.get("components"):
                add(FactNode(node_id=p["precedent_id"], kind="fingerprint",
                             label=p.get("title", p["precedent_id"]), seq=seq,
                             branch_id=p.get("branch_id"), orbit=orbit,
                             attrs={"fingerprint": p.get("fingerprint"),
                                    "components": p.get("components"),
                                    "computed_at": seq}))

        elif et == "case_closed":
            facts.branch_state.setdefault("*", {})["case_status"] = "closed"

    return facts


def materialize(store, case_id: str) -> Facts:
    """Rebuild the projection tables from the canonical log.

    The tables are caches; dropping and rebuilding them must never change any
    decision. ``verify_projection`` in the tests asserts exactly that.
    """
    facts = project(store.events(case_id))
    _write_projection(store, facts)
    return facts


def _write_projection(store, facts: Facts) -> None:
    cur = store.conn.cursor()
    cid = facts.case_id
    cur.execute("DELETE FROM cw.report_section WHERE case_id=%s", (cid,))
    cur.execute("DELETE FROM cw.edge WHERE case_id=%s", (cid,))
    cur.execute("DELETE FROM cw.gate WHERE case_id=%s", (cid,))
    cur.execute("DELETE FROM cw.node WHERE case_id=%s", (cid,))
    for n in facts.nodes.values():
        cur.execute(
            """INSERT INTO cw.node (node_id, case_id, shard_id, kind, label,
                    branch_id, orbit, status, attrs, commit_sha, source_ref,
                    content_hash, created_seq, updated_seq, sealed_seq, sealed_by)
               VALUES (%s,%s,0,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (node_id) DO NOTHING""",
            (n.node_id, cid, n.kind, n.label, n.branch_id, n.orbit, n.status,
             __import__("psycopg").types.json.Jsonb(n.attrs), n.commit_sha,
             n.source_ref, n.content_hash, n.seq, n.seq, n.sealed_seq, n.orbit))
    for e in facts.edges:
        cur.execute(
            """INSERT INTO cw.edge (case_id, src_id, rel, dst_id, attrs,
                    produced_by, created_seq, retired_seq)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
               ON CONFLICT (case_id, src_id, rel, dst_id) DO UPDATE
                 SET retired_seq = EXCLUDED.retired_seq""",
            (cid, e.src_id, e.rel, e.dst_id,
             __import__("psycopg").types.json.Jsonb(e.attrs), e.produced_by,
             e.seq, e.retired_seq))
    for (branch_id, gate_id), row in facts.gate_decisions.items():
        cur.execute(
            """INSERT INTO cw.gate (case_id, branch_id, gate_id, state,
                    predicate, evaluation, decided_by, decided_seq)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
            (cid, branch_id, gate_id, row["state"],
             __import__("psycopg").types.json.Jsonb({}),
             __import__("psycopg").types.json.Jsonb(row.get("evaluation") or {}),
             row.get("decided_by"), row["seq"]))
    store.conn.commit()
