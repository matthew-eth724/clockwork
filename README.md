# Clockwork Engineering — Lite

An evidence-gated, graph-native runtime for multi-agent vulnerability research.

Traditional security graphs describe code, attacks, or stored knowledge.
Clockwork maintains a **live graph of the investigation itself** and uses that
graph to decide what each agent sees, what it may do, what counts as proven,
whether a claim may advance, and what the system carries into the next
investigation.

```
                 ┌─────────────────────────────────────────────────┐
                 │        append-only case events (canonical)      │
                 └───────────────┬─────────────────────────────────┘
                                 │ replay
              ┌──────────────────┼───────────────────┐
      Placement Graph    Case Epistemic Graph   Evidence-Gate Graph
      (ownership,        (claims, evidence,     (12 machine-checked
       affinity,          experiments, controls, transitions, RED/
       replication,       artifacts, commits,    YELLOW/GREEN/STALE)
       placement)         scopes, impacts, fixes)        │
              └──────────────────┼───────────────────┘
                                 │ abstract / duplicate / fix
                        ┌────────▼────────┐
                        │ Precedent Graph │──── Kill Memory (conditional)
                        └─────────────────┘
```

## The four layers

| Layer | Lives in | Controls |
|---|---|---|
| **Placement Graph** | `cw.shard_placement`, `cw.case_artifact_replica`, `clockwork/shards.py` | case ownership, repo affinity, artifact replication, worker eligibility, execution placement |
| **Case Epistemic Graph** | `clockwork/projection.py`, `cw.node`, `cw.edge` | cases, branches, claims, assumptions, evidence, experiments, controls, artifacts, agents, commits, scope snapshots, impacts, fixes, report sections |
| **Evidence-Gate Graph** | `clockwork/gates/` , `cw.gate` | advance / rewind / fork / merge / stale / park / kill |
| **Precedent Graph** | `cw.precedent`, `cw.kill_record`, `clockwork/novelty.py` | vulnerability patterns, duplicate families, known fixes, proof strategies, conditional negative precedent |

## Canonical source of truth

`cw.case_event` is the only authority. It is per-case sequenced, hash-chained to
its predecessor, and the database physically refuses `UPDATE`, `DELETE` and
`TRUNCATE` on it:

```
append-only relation case_event: UPDATE is forbidden
```

Every other table is a projection. The test suite wipes `node`, `edge`, `gate`
and `report_section` and asserts that re-evaluating the same case yields a
byte-identical verdict.

### Event types

`candidate_seeded`, `claim_proposed`, `evidence_added`, `claim_supported`,
`claim_contradicted`, `experiment_requested`, `experiment_completed`,
`control_completed`, `gate_passed`, `gate_failed`, `branch_forked`,
`branch_merged`, `branch_killed`, `branch_parked`, `case_marked_stale`,
`report_packaged`, `human_decision` — plus the supporting events that carry
seals, merges, kills, precedents, scope snapshots and fixes.

### Relationships

`SUPPORTS`, `CONTRADICTS`, `DEPENDS_ON`, `TESTS`, `RULES_OUT`, `GENERATED_BY`,
`VERIFIED_BY`, `BLOCKED_BY`, `INVALIDATED_BY`, `APPLIES_TO_COMMIT`,
`ABSTRACTS_TO`, `DUPLICATE_OF`, `FIXED_BY`, `INCLUDED_IN`.

## The twelve gates

Each gate is a **stored JSON predicate** over the graph, not a checklist.
`clockwork/gates/predicates.py` defines them; `clockwork/gates/engine.py`
evaluates them and returns a per-leaf trace, so a reviewer sees exactly which
condition blocked advancement.

| # | Gate | Decisive condition (abridged) |
|---|---|---|
| 1 | Scope Admission | previous gate · scope snapshot pinned · in scope · lane exists |
| 2 | Surface Mapping | metadata evidence · `TESTS` edge · `APPLIES_TO_COMMIT` |
| 3 | Invariant Definition | ≥2 claims · substantive claim · assumptions declared |
| 4 | Actor and Authority Model | scope claim · actor model · claim `DEPENDS_ON` assumption |
| 5 | Reachability | metadata evidence · `SUPPORTS` edge · experiment requested |
| 6 | Exploit Chain | ≥3 claims · dependency chain depth ≥2 · attack orbit sealed |
| 7 | Local Proof | passing experiment · **full proof binding** · hashed artifact |
| 8 | Falsification and Controls | control held · defense orbit sealed · orbits merged · no open contradictions |
| 9 | Novelty and Duplicate Analysis | structural fingerprint · duplicate checked · kill memory checked · history orbit sealed |
| 10 | Impact and Economics | impact derived · `DEPENDS_ON` claim · impact orbit sealed |
| 11 | Reportability | report sections present · traceable claims · no open contradictions |
| 12 | Final QC and Packaging | independent verifier · **verifier is human** · verifier ≠ author · no orphan report claims · human approved · not self-approved |

### Proof as CI

| State | Meaning |
|---|---|
| `RED` | the proof fails |
| `YELLOW` | the proof works, but reachability, controls, novelty, impact or review remain incomplete |
| `GREEN` | proof, controls, novelty, impact and final QC all pass |
| `STALE` | source, scope, environment, dependency or assumption changed |

Every proof is bound to: source commit, environment, reproduction command,
expected observable, controls and artifact hashes. `local_proof` refuses to pass
while any of those bindings is missing.

## Authority is structural, not procedural

The runtime refuses, by construction:

* an agent submitting a report or contacting a target
  (`submit_report` / `contact_target` are not performable decisions);
* an agent requesting capabilities that would allow either;
* a producer verifying its own evidence
  (`attacker-1 produced ev:self; critical evidence cannot be approved by the
  process that produced it`);
* approving a critical gate from the orbit that produced its evidence;
* mutating output an orbit has already sealed (a fresh lane is required);
* rewriting or erasing events (database-level triggers);
* any write path that mutates projections instead of appending events.

## Blind investigation orbits

| Orbit | Question |
|---|---|
| **Attack** | what is the shortest viable exploit chain? |
| **Defense** | what blocks it, and what else explains the observation? |
| **History** | is this a duplicate, a known fix, an adjacent report? |
| **Impact** | what is the concrete security consequence, derived independently? |

An orbit **seals** its output (`orbit_sealed`, with a hash over its nodes and
edges). Other orbits cannot see that output: it is *structurally absent* from
their context packets, not redacted. Only after a merge event does an orbit's
work become `public` — and merged disagreements are preserved:

* agreement across orbits
* contradictions, and which remain unresolved
* differing assumptions, attributed per orbit
* source-version drift (two orbits bound to different commits)
* unresolved disputes

## Conditional Kill Memory

A kill records: suspected mechanism, blocking claim, supporting evidence,
repository and commit range, the conditions that would invalidate the blocker,
author and an independent verifier. Recording a kill requires all of these and
`author ≠ verifier`.

A kill never permanently suppresses work:

* it only blocks lanes whose structural fingerprint *and* commit range overlap;
* the block states exactly which invalidation condition must be evidenced;
* offering evidence for one of those conditions reopens the lane
  (`kill_challenged`, recorded as `INVALIDATED_BY`).

A kill from a different commit range does not block a new investigation.

## Role-specific context packets

`clockwork/context.py` cuts the **minimum connected subgraph** for one role and
one task: typed anchors, bounded BFS over a whitelisted relation set, node cap,
and structured absence of blind orbits. Full transcripts and whole-case dumps are
never emitted. Packets are explicitly marked `"canonical": false`.

Model-written summaries are **disposable caches** (`cw.summary_cache`), tagged
`[DISPOSABLE CACHE — not evidence]`, keyed to the exact event sequence, and
unusable as evidence — `support_claim` rejects them.

## Reports from the graph

`clockwork/report.py` builds the package by walking provenance:

```
report claim → claim → evidence → experiment (command, env, expected observable)
             → artifact hash → producing activity → independent verification
```

A claim with no `SUPPORTS` evidence raises `UntraceableClaim` — the builder
refuses to emit an attractive but unsupported sentence. The QC verdict always
states `auto_submit: false`, `human_submission_required: true`.

## Novelty fingerprints

Fingerprints are **structural**, not textual:

```
sink | authority | transform | precondition | target
```

`sql-injection` and `sqli` normalise to the same bucket, so two agents describing
the same root cause in different words still collide and cannot dodge duplicate
analysis by rewording a claim.

## Clockwork Lite scope

* PostgreSQL (single physical DB; 64 logical shards via `blake2b(case_id) % 64`)
* append-only case events, claim/evidence graph, 12-gate state machine
* blind Attack + Defense (+ History, Impact) orbits with seals and merges
* conditional Kill Memory, novelty fingerprints, role context packets
* content-addressed artifact store (`sha256`, `var/artifacts/<2>/<hex>`)
* provenance-generated reports
* evidence-clock dashboard

## Running it

```bash
# 1. Postgres (any 17.x instance)
docker run -d --name clockwork-pg \
  -e POSTGRES_PASSWORD=clockwork -e POSTGRES_USER=clockwork \
  -e POSTGRES_DB=clockwork -p 55432:5432 postgres:17-alpine

# 2. Python env
python3 -m venv .venv && ./.venv/bin/pip install -e .
#    or: ./.venv/bin/pip install "psycopg[binary]" fastapi "uvicorn[standard]" jinja2 pytest

# 3. End-to-end scenario (RED → GREEN, violations refused, kill memory, report)
CLOCKWORK_DSN=postgresql://clockwork:clockwork@localhost:55432/clockwork \
  PYTHONPATH=. ./.venv/bin/python -m clockwork.demo

# 4. Invariant tests
PYTHONPATH=. ./.venv/bin/python -m pytest tests -q

# 5. Dashboard + API
PYTHONPATH=. ./.venv/bin/python -m uvicorn clockwork.api:app --port 8899
#    → http://localhost:8899/case/CW-2026-0007
```

### Reset a local database

```bash
docker exec clockwork-pg psql -U clockwork -d clockwork -c "DROP SCHEMA cw CASCADE;"
```

`case_event` refuses `TRUNCATE` by design; dropping the schema is the sanctioned
reset.

## Using it from an agent

`skill/` is an [Agent Skill](https://agentskills.io) that teaches a coding agent
to drive a case end to end: the gate ordering constraints, the API surface, and
the failure modes that cost real debugging time.

```bash
# install for agents that read ~/.agents/skills
mkdir -p ~/.agents/skills
git clone --depth 1 https://github.com/matthew-eth724/clockwork.git /tmp/cw
cp -r /tmp/cw/skill ~/.agents/skills/clockwork-engineering
```

The skill bootstraps the runtime itself — if Clockwork is not installed,
`skill/scripts/ensure-install` clones it, builds the venv, starts Postgres and
boots the schema:

```bash
./scripts/ensure-install --check    # verify only
./scripts/ensure-install --dir DIR  # install to a specific path
```

`skill/scripts/clockwork-run` is a smoke-test CLI and resolves the repo root
from its own location:

```bash
skill/scripts/clockwork-run health
skill/scripts/clockwork-run gates CW-2026-0007 L1-export-idor
skill/scripts/clockwork-run chain CW-2026-0007
skill/scripts/clockwork-run start      # API + dashboard on :8899
```

## Layout

```
clockwork/
  constants.py        events, relationships, gate chain, proof states
  facts.py            immutable fact model returned by replay
  projection.py       events → facts, plus projection cache rebuild
  gates/
    predicates.py     machine-readable transition predicates (stored in DB)
    engine.py         predicate evaluator with per-leaf traces
  context.py          role-specific minimum connected subgraphs
  novelty.py          structural fingerprints and duplicate distance
  killmemory.py       conditional negative precedent, validation, scope
  report.py           provenance-based report generation
  runtime.py          the only mutation path (authority checks + events)
  store.py            Postgres, hash chain, content-addressed artifacts
  shards.py           64 logical shards, placement eligibility
  api.py              HTTP API + dashboard routes
  demo.py             end-to-end scenario
  sql/001_schema.sql  schema, append-only triggers, authority triggers
tests/test_clockwork.py   26 invariant tests
skill/                    Agent Skill: driving a case end to end
web/templates/            evidence-clock dashboard
```

## API surface

```
GET  /api/health
POST /api/actors                      register an actor (ceiling-checked)
POST /api/cases                       open a case (placement + scope snapshot)
GET  /api/cases/{id}/graph            nodes, edges, seals, merges, kills
GET  /api/cases/{id}/clock            event clock + per-branch gate rail
GET  /api/cases/{id}/evaluate/{b}     full per-gate predicate trace
GET  /api/cases/{id}/chain            hash-chain verification
GET  /api/cases/{id}/placement        shard, replicas, worker pool
POST /api/seed /api/claims /api/evidence
POST /api/experiments[/complete] /api/controls
POST /api/gates/decide
POST /api/orbits/seal /api/orbits/merge
POST /api/kills
POST /api/context-packet
GET  /api/cases/{id}/report/{branch}  provenance-generated markdown
```

## Design notes worth knowing

* **Orbit is an activity property, not an authorization claim.** It only decides
  whether already-sealed output may be mutated; permissions come from
  capabilities and gate authority.
* **Merge, not blending.** Two orbits that disagree produce a merge record that
  keeps both positions attributed. Nothing is silently reconciled.
* **A kill is a question with an expiry condition,** not a verdict. It carries the
  commit range it covered and the evidence that would reopen it.
* **The projection is disposable.** If the derived tables and the log ever
  disagree, the log wins; `test_decisions_are_a_pure_function_of_the_log`
  enforces it.
