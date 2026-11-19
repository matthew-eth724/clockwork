# Clockwork runtime API reference

All calls are methods on `clockwork.runtime.Runtime`. Instantiate with
`Runtime()` (reads `CLOCKWORK_DSN`) or `Runtime(Store(dsn))`.

```python
from clockwork.runtime import Runtime, AuthorityError, GateError
from clockwork.report import UntraceableClaim

rt = Runtime()
rt.boot()          # idempotent: creates schema, seeds 64 shards
```

| Exception | Raised when |
|---|---|
| `AuthorityError` | the actor may not perform this action (self-verify, submit, capability expansion, mutating sealed output, unknown actor) |
| `GateError` | a gate predicate is unsatisfied, order violated, lane killed/merged, orbit already sealed, merge of unsealed orbits |
| `UntraceableClaim` | a report claim has no supporting evidence |

Both `AuthorityError` and `GateError` are expected control flow, not crashes.

---

## Actors

```python
rt.register_agent(agent_id, kind, display_name, requested_caps=None)
```

- `kind`: `"human"` | `"agent"` | `"system"`
- `requested_caps`: list of capability strings. Useful values:
  `produce_evidence`, `run_experiment`, `orbit:attack`, `orbit:defense`,
  `orbit:history`, `orbit:impact`.
- **Not grantable, by policy:** `submit_report`, `contact_target`,
  `approve_own_evidence`, `expand_authority`, `erase_evidence`.
  Requesting one raises `AuthorityError`.

Register the human reviewer up front; `final_qc` needs one.

---

## Cases

```python
rt.open_case(case_id, title, repos, scope_snapshot, actor, branches=None)
```

`scope_snapshot` must contain `repo_id` and `commit_sha`. `scope_snapshot_id`
defaults to `scope:<case_id>:0`.

`branches` is a list of `{"branch_id": ..., "label": ..., "repo_id": ...,
"commit_range": ...}`. Declaring lanes up front is optional but keeps the graph
readable.

```python
rt.placement(case_id)   # -> shard_id, physical dsn, replicas, worker_pool
rt.schedule(case_id, branch_id, {"repos": ["repoA"]})
                        # -> eligible, reason, next_gate
```

`shard_for(case_id)` is `blake2b(case_id) % 64` — stable across machines.

```python
rt.facts(case_id, upto_seq=None)   # -> Facts (immutable replay view)
rt.evaluate(case_id, branch_id)    # -> {"state", "gates", "next_gate"}
```

`evaluate()` is your compass. Call it after every meaningful change.

---

## Seeding lanes

```python
rt.seed_candidate(case_id, branch_id, actor, suspected_mechanism,
                  repo_id, commit_range, orbit="attack", label=None)
```

`suspected_mechanism` becomes the report headline. `orbit` decides which orbit
owns the lane node.

---

## Claims and assumptions

```python
rt.propose_claim(case_id, branch_id, claim_id, statement, actor,
                 orbit="attack", claim_class="substantive",
                 depends_on=[], confidence=None)
```

`claim_class`: `substantive` (the finding), `scope` (actor/authority model),
`blocking` (used by kills), `assumption`.

```python
rt.support_claim(case_id, claim_id, evidence_ids, actor, orbit="attack")
rt.contradict_claim(case_id, claim_id, evidence_ids, actor,
                    orbit="defense", reason="")

rt.declare_assumption(case_id, branch_id, assumption_id, statement, actor,
                      falsifiable_by=[...], orbit="attack")
```

`falsifiable_by` cannot be empty — an unfalsifiable assumption is refused.
Gates 3 and 4 require at least one assumption and a `DEPENDS_ON` edge from a
claim to it.

---

## Evidence

```python
rt.add_evidence(case_id, branch_id, evidence_id, actor, kind="metadata",
                supports=[], contradicts=[], rules_out=[],
                commit_sha=None, source_ref=None,
                artifact=None, artifact_media_type="text/plain",
                orbit="attack", label=None, verifies=[])
```

`kind`: `metadata` | `proof` | `control` | `falsification` | `history`.

- `artifact` takes **bytes**. It is stored content-addressed
  (`sha256:<hex>`) and that id is what shows in the report.
- `source_ref` is free-form but conventional: `repo:path/to/file.py:88`.
- `rules_out` is how you retire a contradiction. You never delete evidence —
  you add evidence that rules it out.
- `verifies` is sugar for calling `verify_evidence` on the named ids.

```python
rt.verify_evidence(case_id, evidence_id, verifier, orbit="system")
```

Raises `AuthorityError` if `verifier` is the producer. This is enforced; it is
not advisory.

---

## Experiments

```python
rt.request_experiment(case_id, branch_id, experiment_id, command, environment,
                      expected_observable, actor, tests=[], controls=[],
                      commit_sha=None, orbit="attack")
```

All six bindings are required for `local_proof`: `commit_sha`, `environment`,
`command`, `expected_observable`, non-empty `controls`, and at least one artifact
hash on completion.

```python
rt.complete_experiment(case_id, experiment_id, actor, outcome, observed,
                       artifacts=[b"..."], exit_code=None, orbit="attack")
```

`outcome`: `pass` | `fail` | `error`. Only `pass` counts toward Local Proof.
An experiment can only be completed once; re-run by forking a lane.

---

## Controls

```python
rt.complete_control(case_id, branch_id, control_id, description, kind, result,
                    actor, tests=[], artifact=None, orbit="defense")
```

`kind`: `naive` (does the boring version still work?), `environment` (is this a
staging artefact?), `decoy` (is something else producing the observation?).

`result`: `held` (control behaved as expected) | `broke` (control failed, which
often kills the finding) | `pending`.

`falsification` requires at least one control with `result="held"`.

---

## Orbits

```python
rt.seal_orbit(case_id, orbit, actor)          # one-way; hash recorded
rt.merge_orbits(case_id, actor, orbits=None)  # default ["attack","defense"]
```

`merge_orbits` refuses if any named orbit is unsealed. The merge record contains
`agreement`, `contradictions`, `unresolved_disputes`, `assumptions`,
`differing_assumptions`, `source_version_drift`, `seals`. Read it.

Orbit visibility ladder:

| stage | visible to other orbits |
|---|---|
| not sealed | no |
| sealed | no |
| merged **or** its lane killed | yes (public) |

---

## Context packets

```python
pkt = rt.context_packet(case_id, role=..., agent_id=..., branch_id=...,
                        task=None, extra_anchors=[], use_summary_cache=False)
pkt.to_dict()          # self-contained, "canonical": false
pkt.stats              # nodes, edges, fraction_of_case, depth
pkt.withheld["blinded_orbit_nodes"]
pkt.visible_nodes      # nodes still visible post-blinding, for assertions
```

Roles: `attack_orbit`, `defense_orbit`, `history_orbit`, `impact_orbit`,
`gate_verifier`, `qc_reviewer`.

```python
rt.cache_summary(case_id, scope, text)   # disposable, never evidence
```

---

## Novelty

```python
rt.fingerprint_branch(case_id, branch_id, actor, sink, authority,
                      transform="", precondition="", target="",
                      compare_against=None)
```

Fingerprints are structural: `sink | authority | transform | precondition |
target`, normalised through a synonym table (`sql-injection` -> `sqli`). Two
agents describing the same bug in different words still collide.

A differing `precondition` separates two otherwise-identical mechanisms — that is
what stops one finding masking another.

---

## Kill Memory

```python
rt.kill_branch(case_id, branch_id, actor,
               suspected_mechanism=..., blocking_claim_id=...,
               evidence_ids=[...], invalidation_conditions=[...],
               verifier_id=..., repo_id=None, commit_range=None)

rt.kill_check(case_id, fingerprint_components=..., repo_id=...,
              commit_range=..., offered_evidence=[...])
    # -> KillCheck(blocked, precedent_kill_ids, must_evidence, satisfied_by)

rt.challenge_kill(case_id, kill_id, actor, reason, overriding_evidence=[...])
```

`kill_branch` raises `KillMemoryViolation` unless: all fields present, evidence
ids non-empty, invalidation conditions non-empty, and `verifier_id != author`.

`challenge_kill` refuses an empty `overriding_evidence`.

---

## Staleness, forks, merges

```python
rt.mark_case_stale(case_id, reason, actor, branch_id=None, binding="source")
rt.fork_branch(case_id, parent_branch_id, branch_id, actor, reason,
               at_gate=None, orbit="attack")
rt.merge_branch(case_id, source_branch_id, target_branch_id, actor, resolution=None)
rt.park_branch(case_id, branch_id, actor, reason)
```

`mark_case_stale` forces the branch's derived state to `STALE` until re-proven.
Use it when the commit moves, a dependency is bumped, or the scope changes.

---

## Gates

```python
rt.decide_gate(case_id, branch_id, gate_id, actor, decision="pass", note="")
rt.approve_gate(case_id, branch_id, gate_id, human, note="")
```

`approve_gate` requires a registered `human` and exists because `final_qc`'s
predicate demands a recorded human approval event.

`decide_gate` raises `GateError` whose message lists the failing checks by name,
e.g. `['local_proof predicate unsatisfied: ['artifact_hashed']']`. Look the name
up in `gate-reference.md`.

---

## Reports

```python
pkg = rt.build_report(case_id, branch_id, actor)
pkg["markdown"]       # str
pkg["content_hash"]   # sha256 of the markdown
pkg["qc"]             # gates_passed / gates_unpassed / traceable_claims /
                      # auto_submit: False / human_submission_required: True
```

Sections: summary, invariant break, reproduction, impact, novelty, provenance,
limitations. The provenance section is the audit trail: claim -> evidence ->
experiment -> artifact -> producer -> independent verifier.

---

## Precedent

```python
rt.register_precedent(case_id, precedent_id, kind, title, actor, body=None,
                      fingerprint=None, repo_id=None, conditions=None)
rt.record_fix(case_id, fix_id, description, actor, advisory=None,
              commit_sha=None, repo_id=None, fixes_claims=[])
```

`kind`: `vulnerability_pattern` | `duplicate_family` | `known_fix` |
`proof_strategy` | `negative_precedent`.

---

## Chain integrity

```python
rt.store.verify_chain(case_id)   # -> (ok: bool, note: str)
```

Always run this before reporting. It re-hashes every event and checks the
sequence is gap-free.
