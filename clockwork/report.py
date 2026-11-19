"""Provenance-based report generation.

The report is *generated from the evidence graph*, never written by an agent.
Every important claim in the output carries a trace:

    report claim -> claim -> evidence -> experiment (command, environment,
    expected observable) -> artifact hash -> producing activity -> independent
    verification

A claim that cannot be traced is refused: the builder raises ``UntraceableClaim``
rather than emitting an attractive but unsupported sentence.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from .constants import GATE_CHAIN, GATE_LABELS
from .facts import Facts, FactNode


class UntraceableClaim(Exception):
    pass


def _experiment_trace(exp: FactNode) -> dict[str, Any]:
    return {
        "experiment_id": exp.node_id,
        "command": exp.attrs.get("command"),
        "environment": exp.attrs.get("environment"),
        "expected_observable": exp.attrs.get("expected_observable"),
        "observed": exp.attrs.get("observed"),
        "outcome": exp.attrs.get("outcome"),
        "controls": exp.attrs.get("controls"),
        "artifact_hashes": exp.attrs.get("artifact_hashes"),
        "commit": exp.commit_sha,
    }


def _trace_claim(facts: Facts, claim_id: str) -> dict[str, Any]:
    claim = facts.node(claim_id)
    if not claim:
        raise UntraceableClaim(f"{claim_id} does not exist in the graph")
    traces: list[dict] = []
    for e in facts.edges_to(claim_id, "SUPPORTS"):
        ev = facts.node(e.src_id)
        if not ev:
            continue
        experiments = []
        tested = list(ev.attrs.get("tested_by") or [])
        for eid in tested:
            exp = facts.node(eid)
            if exp and exp.kind == "experiment":
                experiments.append(_experiment_trace(exp))
        for te in facts.edges_to(ev.node_id, "TESTS"):
            exp = facts.node(te.src_id)
            if exp and exp.kind == "experiment":
                experiments.append(_experiment_trace(exp))
        artifacts = []
        for ge in facts.edges_to(ev.node_id, "GENERATED_BY"):
            art = facts.node(ge.src_id)
            if art and art.kind == "artifact":
                artifacts.append({"artifact_id": art.node_id,
                                  "media_type": art.attrs.get("media_type")})
        if ev.content_hash and ev.content_hash.startswith("sha256:"):
            artifacts.append({"artifact_id": ev.content_hash,
                              "media_type": ev.attrs.get("media_type", "text/plain")})
        verifiers = [v for v in (ev.attrs.get("verified_by") or [])]
        for ve in facts.edges_to(ev.node_id, "VERIFIED_BY"):
            if ve.src_id not in verifiers:
                verifiers.append(ve.src_id)
        traces.append({
            "evidence_id": ev.node_id,
            "evidence_kind": ev.attrs.get("evidence_kind"),
            "commit": ev.commit_sha,
            "source_ref": ev.source_ref,
            "experiments": experiments,
            "artifacts": artifacts,
            "produced_by": ev.attrs.get("produced_by"),
            "verified_by": [v for v in verifiers
                            if v != ev.attrs.get("produced_by")],
            "independent_verification": any(
                v != ev.attrs.get("produced_by") for v in verifiers),
        })
    if not traces:
        raise UntraceableClaim(
            f"claim {claim_id} has no SUPPORTS evidence; refusing to emit it "
            f"in a report")
    return {"claim_id": claim_id, "statement": claim.label,
            "claim_class": claim.attrs.get("claim_class"),
            "evidence": traces}


_FORMAT = {
    "summary": 1, "invariant_break": 2, "reproduction": 3,
    "impact": 4, "novelty": 5, "provenance": 6, "limitations": 7,
}


def build_report(runtime, case_id: str, branch_id: str, actor: str) -> dict:
    facts = runtime.facts(case_id)
    branch = facts.node(branch_id)
    if not branch:
        raise UntraceableClaim(f"unknown branch {branch_id}")

    claims = facts.branch_nodes(branch_id, "claim")
    substantive = [c for c in claims if c.attrs.get("claim_class") == "substantive"]
    experiments = facts.branch_nodes(branch_id, "experiment")
    controls = facts.branch_nodes(branch_id, "control")
    impacts = facts.branch_nodes(branch_id, "impact")
    fingerprints = facts.branch_nodes(branch_id, "fingerprint")

    traces = []
    for c in substantive:
        traces.append(_trace_claim(facts, c.node_id))

    gate_states = {g: facts.gate_state(branch_id, g) for g in GATE_CHAIN}
    passing = [e for e in experiments if e.attrs.get("outcome") == "pass"]
    held = [c for c in controls if c.attrs.get("result") == "held"]

    sections: list[dict] = []

    def section(key: str, heading: str, body: str, claim_ids: list[str],
                provenance: dict) -> None:
        sections.append({
            "section_id": f"sec:{key}", "ordinal": _FORMAT[key],
            "heading": heading, "body": body,
            "claim_ids": claim_ids, "provenance": provenance,
            "generated_by": actor,
        })

    # the lane node itself carries the seeded hypothesis
    seeded = facts.node(branch_id)
    mechanism = (seeded.attrs.get("suspected_mechanism")
                 if seeded and seeded.kind == "branch" else "") or ""
    section("summary", "Summary",
            f"Branch `{branch_id}` investigates: {mechanism}\n\n"
            f"Proof state: **{runtime._proof_state(facts, branch_id)}** "
            f"(gates passed: {sum(1 for v in gate_states.values() if v == 'PASSED')}"
            f"/{len(GATE_CHAIN)}).",
            [c.node_id for c in substantive],
            {"claims": [t["claim_id"] for t in traces],
             "evidence_count": sum(len(t["evidence"]) for t in traces)})

    inv_body = "\n".join(f"- {c.label}" for c in claims
                         if c.attrs.get("claim_class") == "substantive")
    section("invariant_break", "Invariant Break",
            inv_body or "_no substantive claims_",
            [c.node_id for c in substantive],
            {"claim_ids": [c.node_id for c in substantive]})

    repro = []
    for e in passing:
        repro.append(
            f"```\n$ {e.attrs.get('command')}\n```\n"
            f"- environment: `{e.attrs.get('environment')}`\n"
            f"- commit: `{e.commit_sha}`\n"
            f"- expected observable: {e.attrs.get('expected_observable')}\n"
            f"- observed: {e.attrs.get('observed')}\n"
            f"- artifacts: {e.attrs.get('artifact_hashes')}")
    section("reproduction", "Reproduction",
            "\n\n".join(repro) or "_no passing experiment bound to this branch_",
            [], {"experiments": [e.node_id for e in passing],
                 "artifact_hashes": [h for e in passing
                                     for h in (e.attrs.get("artifact_hashes") or [])]})

    section("impact", "Impact",
            "\n".join(f"- [{i.attrs.get('severity')}] {i.label}" for i in impacts)
            or "_impact not yet independently derived_",
            [], {"impacts": [i.node_id for i in impacts]})

    fp_lines = []
    for f in fingerprints:
        fp_lines.append(f"- `{f.attrs.get('fingerprint')}` "
                        f"{json.dumps(f.attrs.get('components'), sort_keys=True)}")
    dup = [e for e in facts.live_edges("DUPLICATE_OF")
           if facts.node(e.src_id) and facts.node(e.src_id).branch_id == branch_id]
    section("novelty", "Novelty and Duplicate Analysis",
            "\n".join(fp_lines) or "_no structural fingerprint recorded_",
            [], {"fingerprints": [f.node_id for f in fingerprints],
                 "duplicate_edges": [f"{e.src_id}->{e.dst_id}" for e in dup]})

    prov_lines = []
    for t in traces:
        prov_lines.append(f"### Claim `{t['claim_id']}`\n> {t['statement']}\n")
        for ev in t["evidence"]:
            prov_lines.append(
                f"- evidence `{ev['evidence_id']}` ({ev['evidence_kind']}) "
                f"from `{ev['produced_by']}`, source `{ev['source_ref']}`, "
                f"commit `{ev['commit']}`"
                + (f", verified by {ev['verified_by']}" if ev["verified_by"] else "")
                + ("" if ev["independent_verification"]
                   else ", **independently verified: no**"))
            for x in ev["experiments"]:
                prov_lines.append(
                    f"  - experiment `{x['experiment_id']}`: `{x['command']}` -> "
                    f"{x['outcome']} (artifacts {x['artifact_hashes']})")
            for a in ev["artifacts"]:
                prov_lines.append(f"  - artifact `{a['artifact_id']}`")
    section("provenance", "Claim Provenance",
            "\n".join(prov_lines) or "_no claims_", [],
            {"traces": traces})

    section("limitations", "Limitations and Open Controls",
            "\n".join(f"- gate `{g}` = {s}" for g, s in gate_states.items()
                      if s != "PASSED")
            + ("\n" + "\n".join(f"- control `{c.node_id}` = "
                                f"{c.attrs.get('result')}" for c in controls)
               if controls else "")
            + "\n\n_This report is generated by Clockwork Engineering. It is not "
              "submitted automatically: no agent in this system may submit a "
              "report or contact a target._",
            [], {"gate_states": gate_states,
                 "controls": [c.node_id for c in controls]})

    qc = {
        "gates_passed": {g: s for g, s in gate_states.items() if s == "PASSED"},
        "gates_unpassed": [g for g, s in gate_states.items() if s != "PASSED"],
        "controls_held": [c.node_id for c in held],
        "traceable_claims": len(traces),
        "untraceable_claims": [],
        "auto_submit": False,
        "human_submission_required": True,
    }

    for s in sections:
        runtime._append(case_id, "report_section_generated", actor, {
            "branch_id": branch_id, **s}, orbit="system")

    body = "\n\n".join(f"{'#' * 2} {s['heading']}\n\n{s['body']}" for s in sections)
    content_hash = "sha256:" + hashlib.sha256(body.encode()).hexdigest()
    package_id = f"pkg:{branch_id}:{facts.upto_seq}"
    ev = runtime._append(case_id, "report_packaged", actor, {
        "package_id": package_id, "branch_id": branch_id,
        "content_hash": content_hash, "sections": [s["section_id"] for s in sections],
        "qc_verdict": qc}, orbit="system")
    runtime.store.q(
        """INSERT INTO cw.report_package (package_id, case_id, branch_id,
                content_hash, sections, qc_verdict, generated_by, created_seq)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""",
        (package_id, case_id, branch_id, content_hash,
         [s["section_id"] for s in sections],
         __import__("psycopg.types.json", fromlist=["Jsonb"]).Jsonb(qc),
         actor, ev["seq"]))
    runtime.store.q(
        "UPDATE cw.case SET status='packaged' WHERE case_id=%s AND status='open'",
        (case_id,))
    return {"package_id": package_id, "content_hash": content_hash,
            "markdown": body, "qc": qc, "sections": sections,
            "event_seq": ev["seq"]}
