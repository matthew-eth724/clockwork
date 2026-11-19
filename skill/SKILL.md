---
name: clockwork-engineering
description: Drive a Clockwork Engineering case — open a case, run blind attack/defense orbits, advance branches through the 12 evidence gates, record conditional Kill Memory, and generate a provenance-traced report. Use when a user has Clockwork installed and wants to investigate a vulnerability finding in it, asks "start a clockwork case", "run an orbit", "why won't this gate pass", "record a kill", or "generate the report from the graph".
---

# Clockwork Engineering

Clockwork is an evidence-gated graph runtime for vulnerability research. It does
**not** test targets for you. You do the testing (manually, with Burp, with
scripts); Clockwork decides what counts as proven and produces an auditable
report.

The core thing to internalise: **the graph decides, not you.** You cannot talk a
gate into passing. Either the evidence the predicate asks for exists in the log,
or it doesn't.

## Purpose

Teach an agent to run one investigation end to end:

1. open a case
2. seed hypotheses on lanes
3. run four blind orbits (attack, defense, history, impact)
4. seal and merge them
5. independently verify critical evidence
6. walk the 12 gates
7. record kills so future work isn't silently suppressed
8. generate the report

## Prerequisites

Before step 1, confirm:

- You have the Clockwork repo checked out. `scripts/clockwork-run` resolves the
  repo root from its own location; override with `CLOCKWORK_HOME` if you move it.
- Postgres is reachable. Default DSN: `postgresql://clockwork:clockwork@localhost:55432/clockwork`
  overridable with `CLOCKWORK_DSN`.
- The Python venv exists at `<path>/.venv`.

```bash
cd "$(git rev-parse --show-toplevel)"   # or wherever you cloned clockwork
docker ps --format '{{.Names}}\t{{.Status}}' | grep clockwork-pg || \
  docker run -d --name clockwork-pg \
    -e POSTGRES_PASSWORD=clockwork -e POSTGRES_USER=clockwork \
    -e POSTGRES_DB=clockwork -p 55432:5432 postgres:17-alpine
PYTHONPATH=. ./.venv/bin/python -c "from clockwork.runtime import Runtime; r=Runtime(); r.boot(); print('ready')"
```

Read `references/api-reference.md` before writing any API calls. Read
`references/gate-reference.md` before you attempt to advance a gate — it lists
each gate's exact predicate in plain language.

## Procedure

### Step 0 — Decide which interface you're using

Pick one and stay consistent. Mixing them is fine (same database), but don't
copy IDs across without checking.

- **In-process runtime** (recommended for agents): `Runtime` from Python, see
  `references/api-reference.md`. Fastest, no HTTP, and exceptions are typed.
- **HTTP API**: `uvicorn clockwork.api:app --port 8899`, then `POST`/`GET`.
- **Dashboard** (read-only, for the human): `http://localhost:8899/case/<case_id>`

### Step 1 — Open a case

You need a case id, a repo, and a **scope snapshot including a commit sha**. The
commit is not decoration: evidence gets bound to it, and `STALE` is derived from
it changing.

Call `open_case` with `branches=[...]` declaring your lanes up front. Each lane
carries `repo_id` and `commit_range`.

Verify: `runtime.placement(case_id)` returns a shard id and a primary + replica.

### Step 2 — Seed hypotheses

One `seed_candidate` per hypothesis. The `suspected_mechanism` string becomes the
lane's reportable headline later, so write it as a sentence a reviewer would
understand.

State the **orbit** explicitly. This matters more than it looks — see the
pitfall list.

### Step 3 — Run the attack orbit (blind)

Work in this order or the gates will fight you:

1. `add_evidence(kind="metadata")` for surface mapping — routes, entry points,
   files, with `commit_sha` and `source_ref`. Do this **before** claims that
   depend on it.
2. `propose_claim(claim_class="scope")` — the actor/authority model.
3. `propose_claim(...)` for the invariant being broken, and for the break,
   chaining with `depends_on`.
4. `declare_assumption(...)` — every assumption, with `falsifiable_by`. Gates 3
   and 4 require at least one.
5. `request_experiment(...)` with all six bindings: command, environment,
   expected observable, controls, commit sha, tests-claim.
6. `complete_experiment(...)` with observed result **and artifacts** (bytes).
7. `add_evidence(kind="proof", supports=[claim])` for the result.
8. `support_claim(...)`.

Then `seal_orbit(case_id, "attack", actor)`.

### Step 4 — Run the defense orbit (blind)

The defense agent must **not** be handed attack output. Cut it a packet:

```python
pkt = runtime.context_packet(case_id, role="defense_orbit",
                            agent_id=defender, branch_id=lane)
```

That returns the minimum connected subgraph, with attack claims/evidence/
experiments structurally absent. Check `pkt.withheld["blinded_orbit_nodes"]` to
confirm the blinding actually excluded something.

Defense does the falsification work:

- `complete_control(..., kind="naive"|"environment"|"decoy", result="held"|"broke")`
- contradicts the attack claim if it can (`add_evidence(contradicts=[...], orbit="defense")`)
- declares its own assumptions

Then `seal_orbit(case_id, "defense", defender)`.

### Step 5 — History and impact orbits

History: `fingerprint_branch(...)` (structural, not prose), check duplicates and
known fixes via `register_precedent` / `record_fix`, then seal.

Impact: `derive_impact(...)` with `about_claims=[...]`, then seal.

### Step 6 — Merge

`merge_orbits(case_id, actor, ["attack", "defense", "history", "impact"])`

The merge record preserves agreement, contradictions, differing assumptions, and
source-version drift. Read it — it is where you find out your orbits disagreed.

### Step 7 — Independent verification

`verify_evidence(case_id, evidence_id, verifier)` where `verifier` is **not**
the producer. This will raise `AuthorityError` if you try to self-verify. That
is the point of the system; don't work around it.

### Step 8 — Walk the gates

For each gate in order: `decide_gate(case_id, lane, gate, actor)`.

On `GateError`, the message names the exact unsatisfied checks. Look them up in
`references/gate-reference.md`, supply the missing evidence, retry. Do not
reorder gates or skip one — every predicate checks its predecessor.

Before `final_qc` you must `approve_gate(..., gate_id="final_qc", human)` with a
registered **human** actor.

For the full working sequence, read `references/gate-reference.md` and compare
against the demo script (`clockwork/demo.py`), which is the canonical worked
example.

### Step 9 — Kill Memory (only for dead lanes)

`kill_branch(...)` needs: suspected mechanism, blocking claim, supporting
evidence ids, invalidation conditions, and a verifier who is not the author.

- The invalidation conditions are the whole point. Write conditions that describe
  **what change in the code or environment would make the blocker stop
  applying.** "It's fine" is not a condition.
- A kill only blocks lanes whose fingerprint *and* commit range overlap. A
  differently-worded or differently-committed investigation is not suppressed.
- To reopen: `challenge_kill(..., overriding_evidence=[...])`.

### Step 10 — Produce the report

`runtime.build_report(case_id, lane, actor)` returns markdown with per-claim
provenance. It raises `UntraceableClaim` if any substantive claim has no
`SUPPORTS` evidence — that is a correct refusal, not a bug. Go add the evidence.

The package always reports `auto_submit: false`. **You may not submit it.**
Hand it to the human.

## Pitfalls (each one cost real debugging time)

- **Orbit is an activity property, not a permission.** It only governs whether
  already-sealed output may be mutated. Permissions come from capabilities
  (`produce_evidence`, `run_experiment`, `orbit:<name>`) and gate authority. If
  an agent seems to lack permission, fix capabilities, not the orbit label.
- **After sealing, that orbit may only continue on a new lane.** Mutating a
  pre-seal lane raises `AuthorityError`. Seed a new lane.
- **A lane declared at `open_case` but seeded after a seal is fresh.** Seeding is
  the investigative act; declaration is bookkeeping.
- **Surface-mapping evidence must precede the claims that reference it.** Adding
  evidence with `supports=[claim]` for a claim that doesn't exist yet silently
  leaves the claim unsupported and gate 2 fails later.
- **Every substantive claim needs supports,** or the report builder refuses.
  Including ones you consider obvious, like the invariant statement.
- **Experiment artifacts must be actual bytes,** not a path string. They are
  content-addressed; that hash is what appears in the report.
- **Model summaries are not evidence.** `cache_summary` is disposable and keyed to
  a specific event sequence. Never cite it.
- **Don't edit the log.** `case_event` refuses UPDATE/DELETE/TRUNCATE at the
  database level. Reset by dropping the schema.

## Bundled resources

- `references/api-reference.md` — every runtime method with its required args.
- `references/gate-reference.md` — the 12 gates, their exact conditions, and the
  evidence that satisfies each.
- `scripts/clockwork-run` — thin CLI wrapper: health check, open a case, run the
  demo, tail a case's gate state. Good for smoke-testing the install.

## Validation checklist

Before telling the user you're done:

- [ ] `runtime.evaluate(case_id, lane)["state"]` is `GREEN` (or you can explain
      exactly which gate is open and why)
- [ ] `runtime.store.verify_chain(case_id)` returns verified — the log is intact
- [ ] Every substantive claim in the report has provenance to source ref,
      experiment command, and artifact hash
- [ ] Critical evidence was verified by someone other than its producer
- [ ] You did **not** submit anything; the package is handed to a human
- [ ] If you killed a lane, its invalidation conditions describe a real code or
      environment change
