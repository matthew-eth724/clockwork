"""Clockwork Lite demonstration scenario.

One case, four blind orbits, a full 12-gate walk to GREEN, a Kill Memory record
with a later valid challenge, and a provenance-generated report.

Run: ``python -m clockwork.demo``  (needs the Postgres container up)
"""
from __future__ import annotations

import json
import sys

from .runtime import AuthorityError, GateError, Runtime
from .constants import GATE_CHAIN, GATE_LABELS

CASE = "CW-2026-0007"
REPO = "svc-billing"
COMMIT = "9f2c1ab3d4e5f60718293a4b5c6d7e8f90a1b2c3"

BOLD = "\033[1m"
DIM = "\033[2m"
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
OFF = "\033[0m"


def hr(title: str) -> None:
    print(f"\n{BOLD}{CYAN}── {title} {'─' * max(0, 68 - len(title))}{OFF}")


def scenario(rt: Runtime) -> dict:
    out: dict = {}

    # ---------------------------------------------------------------- setup
    hr("0. Actors, case, placement")
    rt.register_agent("human:reviewer", "human", "Dana Okonjo (reviewer)", ["approve"])
    rt.register_agent("attacker-1", "agent", "Attack Orbit", 
                      ["produce_evidence", "run_experiment", "orbit:attack"])
    rt.register_agent("defender-1", "agent", "Defense Orbit",
                      ["produce_evidence", "run_experiment", "orbit:defense"])
    rt.register_agent("historian-1", "agent", "History Orbit",
                      ["produce_evidence", "orbit:history"])
    rt.register_agent("impact-1", "agent", "Impact Orbit",
                      ["produce_evidence", "orbit:impact"])

    rt.open_case(
        CASE, "Tenant isolation break in invoice export",
        [REPO],
        {"repo_id": REPO, "commit_sha": COMMIT, "scope_snapshot_id": f"scope:{CASE}:1",
         "in_scope": ["svc-billing"], "excluded": ["payment-processor"]},
        "human:reviewer",
        branches=[{"branch_id": "main", "label": "main"},
                  {"branch_id": "L1-export-idor", "label": "export idor",
                   "repo_id": REPO, "commit_range": COMMIT},
                  {"branch_id": "L2-pdf-tpl", "label": "pdf template ssti",
                   "repo_id": REPO, "commit_range": COMMIT}],
    )
    plc = rt.placement(CASE)
    out["placement"] = plc
    print(f"  case {CASE} -> shard {plc['shard_id']} "
          f"(replica {[r['shard_id'] for r in plc['replicas'] if r['role']=='replica']})")

    # ------------------------------------------------- orbits run blind, in turn
    hr("1. ATTACK ORBIT (blind)")
    rt.seed_candidate(CASE, "L1-export-idor", "attacker-1",
                      "cross-tenant invoice read (IDOR) via /invoices/{id}",
                      REPO, COMMIT)
    rt.request_experiment(
        CASE, "L1-export-idor", "exp-export-anon", 
        "make repro-export INVOICE=INV-1002 AS=tenant-a   # local fixture only",
        "local docker compose @ commit 9f2c1ab", "HTTP 403 for foreign invoice",
        "attacker-1", tests=["claim:idor"], controls=["ctl-naive"],
        commit_sha=COMMIT)
    rt.complete_experiment(
        CASE, "exp-export-anon", "attacker-1", "pass",
        "HTTP 200 with tenant B's invoice body (customer, amounts, VAT id)",
        artifacts=[b'{"invoice":"INV-1002","tenant":"B","total":18400.00}\n'],
        exit_code=0)
    rt.add_evidence(CASE, "L1-export-idor", "ev:route-map", "attacker-1",
                    kind="metadata", supports=["claim:scope-model"], commit_sha=COMMIT,
                    source_ref=f"{REPO}:app/routes/invoices.py:41")
    rt.add_evidence(CASE, "L1-export-idor", "ev:reach", "attacker-1",
                    kind="metadata", supports=[], commit_sha=COMMIT,
                    source_ref=f"{REPO}:app/routes/invoices.py:12")
    rt.propose_claim(CASE, "L1-export-idor", "claim:scope-model",
                     "Role 'tenant-admin' can reach /invoices/{id} without a "
                     "tenant binding predicate in the query", "attacker-1",
                     claim_class="scope",
                     depends_on=["asm:actor-model"])
    rt.propose_claim(CASE, "L1-export-idor", "claim:invariant",
                     "Every invoice read must be constrained by tenant_id = "
                     "session.tenant_id (invariant INV-TENANT-1)", "attacker-1",
                     claim_class="substantive", depends_on=["claim:scope-model"])
    rt.propose_claim(CASE, "L1-export-idor", "claim:idor",
                     "GET /invoices/{id} returns another tenant's invoice for an "
                     "authenticated tenant-admin (INV-TENANT-1 violated)",
                     "attacker-1", claim_class="substantive",
                     depends_on=["claim:invariant", "claim:scope-model"])
    rt.declare_assumption(CASE, "L1-export-idor", "asm:actor-model",
                          "Only tenant admins can authenticate to /invoices/*",
                          "attacker-1",
                          falsifiable_by=["anonymous request returns 401"])
    rt.add_evidence(CASE, "L1-export-idor", "ev:sink-src", "attacker-1",
                    kind="metadata", supports=["claim:idor", "claim:invariant"],
                    commit_sha=COMMIT,
                    source_ref=f"{REPO}:app/services/invoices.py:88")
    rt.add_evidence(CASE, "L1-export-idor", "ev:exp-pass", "attacker-1",
                    kind="proof", supports=["claim:idor"],
                    commit_sha=COMMIT, source_ref="artifact:exp-export-anon",
                    artifact=b'{"invoice":"INV-1002","tenant":"B"}\n',
                    artifact_media_type="application/json")
    rt.support_claim(CASE, "claim:idor", ["ev:exp-pass"], "attacker-1")
    rt.seed_candidate(CASE, "L3-self-approve", "attacker-1",
                      "self-approval probe (fresh lane after seal)", REPO, COMMIT)
    rt.seal_orbit(CASE, "attack", "attacker-1")
    print(f"  attack orbit sealed ({len(rt.facts(CASE).seals['attack']['node_ids'])} nodes)")

    hr("2. DEFENSE ORBIT (blind to attack output)")
    pkt = rt.context_packet(CASE, role="defense_orbit", agent_id="defender-1",
                            branch_id="L1-export-idor",
                            task={"goal": "find blockers and alternative explanations"})
    vis = pkt.visible_nodes
    # the lane node is a shared structural anchor; the blindness claim is about
    # the attack orbit's *claims, evidence and experiments*
    leaked = [n for n in vis if n.get("orbit") == "attack"
              and n.get("kind") != "branch"]
    print(f"  defense packet: {pkt.stats['nodes']} nodes/"
          f"{pkt.stats['full_case_nodes']} case nodes "
          f"({pkt.stats['fraction_of_case']:.0%}); "
          f"attack claims/evidence/experiments visible: {RED}{len(leaked)}{OFF}")
    print(f"  visible: {[n['id'] for n in vis]}")
    rt.complete_control(CASE, "L1-export-idor", "ctl-naive",
                        "Request own invoice INV-1001 (expect 200)", "naive",
                        "held", "defender-1", tests=["claim:idor"],
                        artifact=b'{"invoice":"INV-1001","tenant":"A"}\n')
    rt.complete_control(CASE, "L1-export-idor", "ctl-tenant-b-session",
                        "Request INV-1002 as tenant B (expect 200)",
                        "environment", "held", "defender-1",
                        tests=["claim:idor"])
    rt.complete_control(CASE, "L1-export-idor", "ctl-gateway",
                        "Is the 200 produced by a cache/gateway rewrite? Disable "
                        "edge cache and replay", "decoy", "held", "defender-1",
                        tests=["claim:idor"])
    rt.add_evidence(CASE, "L1-export-idor", "ev:def-cache", "defender-1",
                    kind="control", supports=["claim:idor"],
                    contradicts=[], rules_out=["claim:alt-cache"],
                    commit_sha=COMMIT, source_ref="control:ctl-gateway",
                    orbit="defense")
    rt.add_evidence(CASE, "L1-export-idor", "ev:def-blocker", "defender-1",
                    kind="control", supports=["claim:idor"],
                    commit_sha=COMMIT, source_ref="ransack:app/services/invoices.py:88",
                    orbit="defense")
    rt.add_evidence(CASE, "L1-export-idor", "ev:def-packet", "defender-1",
                    kind="control", supports=["claim:idor"],
                    commit_sha=COMMIT, source_ref="control:ctl-tenant-b-session",
                    orbit="defense")
    rt.seal_orbit(CASE, "defense", "defender-1")
    print("  defense orbit sealed")

    hr("3. HISTORY ORBIT + Kill Memory (blind)")
    rt.fingerprint_branch(CASE, "L1-export-idor", "historian-1",
                          sink="idor", authority="authenticated",
                          transform="direct", precondition="tenant-admin",
                          target="invoice-read")
    rt.register_precedent(CASE, "prec:dup-family-invoices", "duplicate_family",
                          "Invoice tenant-boundary family (2024-2026)",
                          "historian-1", fingerprint="fp0:invoices",
                          repo_id=REPO)
    # a *prior* kill from an earlier investigation, kept as negative precedent
    rt.seal_orbit(CASE, "history", "historian-1")
    rt.merge_orbits(CASE, "human:reviewer", ["attack", "defense"])
    _m = rt.facts(CASE).merges[-1]["resolution"]
    print(f"  conflict preserved: contradictions={len(_m['contradictions'])} "
          f"differing_assumptions={[x['statement'][:38] + '…' for x in _m['differing_assumptions']]}")
    merged = rt.facts(CASE).merges[-1]["resolution"]
    print(f"  merged: agreement={len(merged['agreement'])} "
          f"contradictions={len(merged['contradictions'])} "
          f"differing_assumptions={len(merged['differing_assumptions'])} "
          f"version_drift={len(merged['source_version_drift'])}")

    hr("4. IMPACT ORBIT")
    rt.derive_impact(CASE, "L1-export-idor", "impact:1",
                     "Cross-tenant read of invoices incl. customer PII and VAT ids",
                     "high", "impact-1", about_claims=["claim:idor"],
                     economics={"tenants_affected": "all", "records": "unbounded",
                                "regulatory": ["GDPR Art.32", "SOC2 CC6.1"]})
    rt.seal_orbit(CASE, "impact", "impact-1")
    rt.merge_orbits(CASE, "human:reviewer", ["attack", "defense", "history", "impact"])

    # ------------------------------------------------------- independent verify
    hr("5. Independent verification of critical evidence")
    rt.verify_evidence(CASE, "ev:exp-pass", "human:reviewer")
    rt.verify_evidence(CASE, "ev:sink-src", "defender-1")
    rt.verify_evidence(CASE, "ev:def-cache", "human:reviewer")
    print("  critical evidence independently verified")

    # ------------------------------------------------------------------ gates
    hr("6. Evidence gates (machine predicates)")
    results = []
    for gate in GATE_CHAIN:
        try:
            rt.decide_gate(CASE, "L1-export-idor", gate, "human:reviewer")
        except GateError as exc:
            print(f"  {RED}✗ {GATE_LABELS[gate]}{OFF}: {exc}")
            results.append((gate, "FAILED"))
            continue
        print(f"  {GREEN}✓ {GATE_LABELS[gate]}{OFF}")
        results.append((gate, "PASSED"))
    # final QC requires a human approval event, not just a producer
    rt.evaluate(CASE, "L1-export-idor")
    rt.approve_gate(CASE, "L1-export-idor", "final_qc", "human:reviewer",
                    note="signed off")
    try:
        rt.decide_gate(CASE, "L1-export-idor", "final_qc", "human:reviewer")
        print(f"  {GREEN}✓ {GATE_LABELS['final_qc']} (human approved){OFF}")
    except GateError as exc:
        print(f"  {RED}✗ final QC: {exc}{OFF}")

    # merge sealed orbits (falsification gate requires the blind merge)
    rt.merge_orbits(CASE, "human:reviewer", ["attack", "defense", "history", "impact"])

    # ------------------------------------------- attempted violations (caught)
    hr("7. Policy violations are refused by construction")
    violations = []

    try:
        # a fresh lane is legitimate continuance; using it to self-approve is not
        rt.add_evidence(CASE, "L3-self-approve", "ev:self", "attacker-1",
                        kind="proof")
        rt.verify_evidence(CASE, "ev:self", "attacker-1")
    except AuthorityError as exc:
        violations.append(("self-approval", str(exc)))
        print(f"  {YELLOW}blocked{OFF} self-approval: {exc}")

    try:
        rt.add_evidence(CASE, "L1-export-idor", "ev:late", "attacker-1",
                        kind="proof", supports=["claim:idor"])
    except AuthorityError as exc:
        violations.append(("sealed-output-mutation", str(exc)))
        print(f"  {YELLOW}blocked{OFF} sealed output: {exc}")

    try:
        rt.human_decision(CASE, "submit_report", "attacker-1")
    except AuthorityError as exc:
        violations.append(("auto-submit", str(exc)))
        print(f"  {YELLOW}blocked{OFF} auto-submit: {exc}")

    try:
        rt.human_decision(CASE, "contact_target", "human:reviewer")
    except AuthorityError as exc:
        violations.append(("contact-target", str(exc)))
        print(f"  {YELLOW}blocked{OFF} target contact: {exc}")

    try:
        rt.register_agent("rogue", "agent", "Rogue", ["submit_report"])
    except AuthorityError as exc:
        violations.append(("self-expand", str(exc)))
        print(f"  {YELLOW}blocked{OFF} capability expansion: {exc}")

    try:
        rt.store.q("UPDATE cw.case_event SET event_type='x' WHERE case_id=%s",
                   (CASE,))
    except Exception as exc:  # noqa: BLE001 - psycopg raises RaiseError
        violations.append(("erase-evidence", str(exc).splitlines()[0]))
        print(f"  {YELLOW}blocked{OFF} event tampering: "
              f"{str(exc).splitlines()[0]}")

    try:
        rt.decide_gate(CASE, "L2-pdf-tpl", "local_proof", "attacker-1")
    except (GateError, AuthorityError) as exc:
        violations.append(("gate-skip", str(exc)[:120]))
        print(f"  {YELLOW}blocked{OFF} gate skip: {str(exc)[:110]}")

    out["violations"] = violations

    # ----------------------------------------------------------- kill memory
    hr("8. Conditional Kill Memory")
    # L2 lane: PDF template SSTI — killed because the renderer is sandboxed.
    rt.seed_candidate(CASE, "L2-pdf-tpl", "attacker-1",
                      "pdf template ssti", REPO, COMMIT)
    rt.propose_claim(CASE, "L2-pdf-tpl", "claim:tpl-sink",
                     "Invoice PDF template evaluates user strings as Jinja2",
                     "attacker-1")
    rt.add_evidence(CASE, "L2-pdf-tpl", "ev:tpl-escape", "defender-1",
                    kind="control", rules_out=["claim:tpl-sink"],
                    commit_sha=COMMIT, source_ref=f"{REPO}:pdf/render.py:30",
                    orbit="defense")
    rt.request_experiment(CASE, "L2-pdf-tpl", "exp:tpl-probe",
                          "render invoice with '{{7*7}}' in the notes field",
                          "local compose", "49 rendered into the PDF",
                          "attacker-1", tests=["claim:tpl-sink"],
                          commit_sha=COMMIT)
    rt.complete_experiment(CASE, "exp:tpl-probe", "attacker-1",
                           "fail", "output shows literal '{{7*7}}' -> sandboxed",
                           artifacts=[b"%PDF-1.4 literal {{7*7}}\n"], exit_code=0)
    kill = rt.kill_branch(
        CASE, "L2-pdf-tpl", "defender-1",
        suspected_mechanism="pdf template injection via invoice notes",
        blocking_claim_id="claim:tpl-sink",
        evidence_ids=["ev:tpl-escape", "exp:tpl-probe"],
        invalidation_conditions=[
            "renderer switches from sandboxed Jinja2 to native f-string",
            "notes field becomes a template source rather than a value",
        ],
        verifier_id="human:reviewer", repo_id=REPO, commit_range=COMMIT)
    krec = rt.facts(CASE).kills[kill["payload"]["kill_id"]]
    print(f"  kill {krec['kill_id']} verified by {krec['verifier_id']} "
          f"(author {krec['author_id']})")

    chk = rt.kill_check(CASE,
                        fingerprint_components=krec["components"],
                        repo_id=REPO, commit_range=COMMIT,
                        offered_evidence=[])
    print(f"  new lane with no new evidence -> {RED}blocked{OFF}: "
          f"must supply {chk.must_evidence}")
    chk2 = rt.kill_check(CASE,
                         fingerprint_components=krec["components"],
                         repo_id=REPO, commit_range="different-commit",
                         offered_evidence=[])
    print(f"  same mechanism, different commit range -> blocked="
          f"{chk2.blocked} (scope of the blocker matters)")
    rt.challenge_kill(CASE, krec["kill_id"], "human:reviewer",
                      "renderer replaced with native f-string in 9f2c1ab",
                      overriding_evidence=["invalidation_conditions[0]"])
    print(f"  kill reopened with evidence addressing "
          f"'{krec['invalidation_conditions'][0]}'")
    out["kill"] = krec

    # --------------------------------------------------------------- report
    hr("9. Report from the evidence graph")
    # reportability needs a draft; final QC then verifies the package
    draft = rt.build_report(CASE, "L1-export-idor", "human:reviewer")
    try:
        rt.decide_gate(CASE, "L1-export-idor", "reportability", "human:reviewer")
        print(f"  {GREEN}✓ Reportability{OFF} (draft traces every claim)")
    except GateError as exc:
        print(f"  {RED}✗ Reportability{OFF}: {exc}")
    pkg = rt.build_report(CASE, "L1-export-idor", "human:reviewer")
    out["report"] = pkg
    print(f"  package {pkg['package_id']} sha256={pkg['content_hash'][7:19]}…")
    print(f"  qc: traceable_claims={pkg['qc']['traceable_claims']} "
          f"gates_unpassed={pkg['qc']['gates_unpassed']}")
    print(f"  auto_submit={pkg['qc']['auto_submit']} "
          f"human_submission_required={pkg['qc']['human_submission_required']}")

    hr("10. Final QC, then chain integrity")
    rt.approve_gate(CASE, "L1-export-idor", "final_qc", "human:reviewer",
                    note="package verified against graph")
    try:
        rt.decide_gate(CASE, "L1-export-idor", "final_qc", "human:reviewer")
        print(f"  {GREEN}✓ Final QC and Packaging{OFF} — human approval recorded")
    except (GateError, AuthorityError) as exc:
        print(f"  {RED}✗ Final QC{OFF}: {exc}")

    hr("11. Chain integrity")
    ok, why = rt.store.verify_chain(CASE)
    print(f"  {GREEN if ok else RED}{why}{OFF}")
    out["chain"] = (ok, why)
    out["final_state"] = rt.evaluate(CASE, "L1-export-idor")
    print(f"  final branch state: {BOLD}{out['final_state']['state']}{OFF}")
    saved = rt.store.put_artifact(CASE, pkg["markdown"].encode(),
                                  "text/markdown", "human:reviewer")
    print(f"  raw report artifact: {saved}")
    return out


def main() -> None:
    rt = Runtime()
    rt.boot()
    scenario(rt)


if __name__ == "__main__":
    main()
