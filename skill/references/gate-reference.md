# The 12 evidence gates

Each gate is a JSON predicate stored in `cw.gate.predicate` and evaluated against
the graph. `rt.evaluate(case_id, lane)["gates"][gate_id]["checks"]` returns every
leaf with a pass/fail and a human-readable reason, so you can always see exactly
what is missing.

**Every gate checks its predecessor.** You cannot skip. The first unsatisfied
gate in the chain is your `next_gate`.

Print the live predicate at any time:

```python
from clockwork.gates.predicates import GATE_PREDICATES
import json; print(json.dumps(GATE_PREDICATES["local_proof"], indent=2))
```

---

## 1. Scope Admission

**Proves:** this lane is legitimately in scope and bound to a specific source
version.

Requires:
- `scope_snapshot` node exists (captured at `open_case`)
- case not marked stale
- lane node exists

**Satisfied by:** opening the case properly.

---

## 2. Surface Mapping

**Proves:** you actually looked at the code, and the lane's claims are anchored
to a commit.

Requires:
- `scope_snapshot` exists
- ≥1 evidence node
- a `TESTS` edge from an experiment to a claim
- an `APPLIES_TO_COMMIT` edge from evidence to a commit

**Satisfied by:** `add_evidence(commit_sha=...)` — evidence carrying a commit
automatically gets the `APPLIES_TO_COMMIT` edge — plus one
`request_experiment(tests=[claim])`.

**Common failure:** evidence added with `supports=[claim]` before the claim
exists. The edge is silently absent. Create claims first, or accept that the
evidence is unsupported.

---

## 3. Invariant Definition

**Proves:** you can name the rule that was broken, and you've stated your
assumptions rather than smuggling them.

Requires:
- ≥2 claims on the lane
- ≥1 claim with `claim_class="substantive"` (the invariant break)
- ≥1 assumption

**Satisfied by:** `propose_claim` twice + `declare_assumption`.

An assumption with no `falsifiable_by` is refused at write time.

---

## 4. Actor and Authority Model

**Proves:** you know *who* can do this, not just that a code path exists.

Requires:
- ≥1 claim with `claim_class="scope"`, **or** a claim whose text contains "actor"
- a `DEPENDS_ON` edge from a claim to an assumption

**Satisfied by:** `propose_claim(claim_class="scope", ...)` and chaining a real
claim onto an assumption via `depends_on`.

---

## 5. Reachability

**Proves:** something actually reaches the sink in the deployed configuration.

Requires:
- ≥1 evidence node of `kind="metadata"`
- ≥1 `SUPPORTS` edge from evidence to a claim
- ≥1 experiment requested (any outcome)

**Satisfied by:** route-map style evidence plus one experiment.

---

## 6. Exploit Chain

**Proves:** there is a chain, not an isolated code smell.

Requires:
- ≥3 claims
- dependency chain depth ≥2 (`DEPENDS_ON` between claims on the lane)
- attack orbit sealed

**Satisfied by:** substantiate -> reach -> exploit, chained with `depends_on`,
then `seal_orbit("attack")`.

---

## 7. Local Proof

**Proves:** the exploit actually works here.

Requires:
- ≥1 experiment with `outcome="pass"`
- **proof binding complete** — every experiment has `commit_sha`, `environment`,
  `command`, `expected_observable`, non-empty `controls`, non-empty
  `artifact_hashes`, and `outcome=pass`
- ≥1 hashed artifact

**Satisfied by:** a fully-specified `request_experiment` and a
`complete_experiment(artifacts=[bytes])`.

**This is the gate that fails most often.** The error names the missing field.
If you passed `artifacts=["/tmp/out.json"]` (a string), it never became bytes and
no hash exists. Pass the file's contents.

---

## 8. Falsification and Controls

**Proves:** you tried to break your own finding. This is the defense orbit's
territory and it must be blind to the attack result when it starts.

Requires:
- ≥1 control with `result="held"`
- defense orbit sealed
- **orbits merged** — `merge_orbits` must include attack and defense
- no open contradictions (or as many `RULES_OUT` edges as `CONTRADICTS` edges)

**Satisfied by:** `complete_control(kind="decoy", result="held")` +
`seal_orbit("defense")` + `merge_orbits`. Contradictions you leave open will
block this forever — either rule them out with evidence or accept the finding is
dead.

---

## 9. Novelty and Duplicate Analysis

**Proves:** this isn't the third report of the same bug.

Requires:
- ≥1 fingerprint node on the lane
- duplicate checked — a precedent of kind `duplicate_family` or
  `vulnerability_pattern` exists, or a `DUPLICATE_OF` edge
- kill memory checked — if kills exist, at least one is challenged/overridden;
  if no kills exist, passes automatically
- history orbit sealed

**Satisfied by:** `fingerprint_branch(...)` + `register_precedent(...)` +
`seal_orbit("history")`.

**Note on kill memory:** an unchallenged kill on this case blocks the gate. That
is intentional — you must explain why the old blocker no longer applies.

---

## 10. Impact and Economics

**Proves:** the security consequence was derived independently, not copied from
the attack orbit's optimism.

Requires:
- ≥1 impact node on the lane
- a `DEPENDS_ON` edge from impact to a claim
- impact orbit sealed

**Satisfied by:** `derive_impact(about_claims=[claim], ...)` +
`seal_orbit("impact")`.

---

## 11. Reportability

**Proves:** a report can be generated that traces every claim.

Requires:
- ≥3 report sections generated
- ≥1 traced claim (claim with `SUPPORTS` evidence or a `GENERATED_BY` producer)
- no open contradictions

**Satisfied by:** call `build_report` once (this writes sections and package),
then `decide_gate(..., "reportability", ...)`. The measure-then-judge order is
deliberate: you cannot claim reportability before a report exists.

`build_report` refuses if any substantive claim is unsupported. Fix the evidence,
not the claim text.

---

## 12. Final QC and Packaging

**Proves:** someone who did not do the work checked it, and a human signed off.

Requires:
- an independent verifier exists — someone who verified evidence and is not a
  producer, an experiment requester, or a claim proposer
- that verifier is a registered `human`
- `verifier_not_author`
- no orphan report claims (every report section's claims exist and have
  `SUPPORTS` edges)
- human approved — an `approve_gate` event
- not self-approved

**Satisfied by:**
```python
rt.verify_evidence(case_id, "ev:exp-pass", "human:reviewer")
rt.approve_gate(case_id, lane, "final_qc", "human:reviewer", note="signed off")
rt.decide_gate(case_id, lane, "final_qc", "human:reviewer")
```

---

## Derived branch state

| State | Condition |
|---|---|
| `RED` | no passing experiment |
| `YELLOW` | experiment passes, but not all 12 gates |
| `GREEN` | experiment passes and all 12 gates pass |
| `STALE` | `mark_case_stale` recorded against the lane |

`YELLOW` is not failure — it is "working but not yet defensible". Do not tell a
user a finding is ready at `YELLOW`.

---

## Recovering a stuck lane

1. `rt.evaluate(case_id, lane)` -> find `next_gate`
2. Print that gate's `checks`, read the failing `check` names
3. Match the name against the section above
4. Supply the missing evidence
5. Re-run `decide_gate`

If the missing thing is an independent human verifier and no human is available,
**stop and ask the user.** Do not register a fake human actor to clear the gate.
