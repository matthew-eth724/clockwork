# Clockwork Engineering — agent instructions

Read this before changing anything. It is the short version of what building
this cost to learn.

## What this is

An evidence-gated graph runtime for vulnerability research. The append-only
event log (`cw.case_event`) is the only source of truth. Every other table is a
projection that must be reproducible from that log.

**The governing rule:** projections are disposable, decisions must not be. If
you change how something is computed, the same log must still yield the same
verdict — or you have changed the truth, and that needs to be deliberate.

## Setup

```bash
skill/scripts/ensure-install        # idempotent: locate or install
skill/scripts/clockwork-run health  # postgres up, 64 shards, schema ready
```

Postgres runs in container `clockwork-pg` on port 55432. Reset with
`skill/scripts/clockwork-run reset` (it asks for confirmation).

## Running tests

```bash
PYTHONPATH=. ./.venv/bin/python -m pytest tests -q
```

Run the smallest test that proves your change. Do not re-run green checks.

```bash
PYTHONPATH=. ./.venv/bin/python -m clockwork.demo   # end-to-end, RED -> GREEN
scripts/check-responsive                            # layout at 12 widths
```

## The database may hold the user's real work

`clockwork-run reset` drops the whole `cw` schema. This destroyed 22 cases
including a live investigation once. Treat the database as precious:

- **Back up before anything destructive:** `scripts/backup` (dumps and verifies).
- **Never reset to "clean up" after a test.** Use a throwaway case id instead.
- **The reset command now refuses** when non-demo cases exist. Do not reach for
  `--force` to get past that guard; it is telling you something.
- Verification restores into a throwaway container and replays the log. If you
  change the projection, re-run `scripts/backup` and confirm old dumps still
  verify — a projection change can break replay of historical data.

## Traps that cost real debugging time

These are not hypothetical. Each one bit during construction.

**Silent projection gaps.** A `branch_nodes(branch, "branch")` returns nothing —
the lane node has `branch_id == node_id`, so it is never "on" itself. Use
`facts.node(branch_id)`. Similarly, evidence added with `supports=[claim]` for a
claim that does not exist yet leaves the claim unsupported with no error.

**Orbit is an activity property, not a permission.** It only governs whether
already-sealed output may be mutated. Permissions come from capabilities
(`produce_evidence`, `orbit:<name>`) and gate authority. Do not "fix" an
authorization problem by relabelling an orbit.

**Sealing is one-way.** After `seal_orbit`, that activity may only continue on a
lane created (seeded) after the seal. A lane *declared* at `open_case` but
*seeded* afterwards counts as fresh — declaration is bookkeeping, seeding is the
act.

**Blindness is structural, not cosmetic.** Other-orbit nodes must be absent from
a context packet, not blanked. When touching `context.py`, verify with
`pkt.withheld["blinded_orbit_nodes"]` and `pkt.visible_nodes`. A `forbidden_orbits`
pre-filter that short-circuits before the blindness check makes it *appear* to
work while doing nothing.

**FactNode is `eq=False` deliberately.** Identical labels must not compare equal.
Do not "tidy" that away.

**Fixtures that seed before `case_opened`** are invisible to the attribute-merge
path. If a lane is missing its `suspected_mechanism` in a report, check event
order first.

## Never do this

- **Never mutate projections instead of appending events.** All writes go
  through `Runtime`. There is no second path, and adding one breaks the audit
  trail.
- **Never let an actor approve its own critical evidence.** `verify_evidence`
  enforces producer != verifier. Do not add an escape hatch, and do not register
  a fake human to clear `final_qc`.
- **Never auto-submit or contact a target.** The runtime refuses these by design.
  Reports are handed to a human.
- **Never `TRUNCATE`/`UPDATE`/`DELETE` `cw.case_event`.** Triggers block it. To
  reset, drop the schema.
- **Never weaken a gate predicate to make a test pass.** If a gate is hard to
  satisfy, the fixture is incomplete, not the gate.

## Conventions

- `branch_nodes()` includes inherited nodes. Use `owns()` when you need
  authorship specifically (reports, provenance). A fork inherits its parent's
  claims/assumptions/evidence/controls/experiments as `DEPENDS_ON` edges with
  `kind=inheritance`; it inherits no gates, seals or kills.
- `projection.edge()` dedupes on `(src, rel, dst)`, matching the UNIQUE constraint
  on `cw.edge`. Two write paths can express the same link; without dedupe every
  count over `facts.edges` double-counts. Do not remove that guard.
- Canonical JSON for anything hashed (`store.canonical_json`).
- Any new event type must be added to `constants.EVENT_TYPES` *and* handled in
  `projection.project()`. A type that is appended but not projected is a silent
  hole — it is still in the log, so the chain verifies and nothing looks wrong.

  **Fixed:** `claim_supported` and `claim_contradicted` now project to real
  `SUPPORTS`/`CONTRADICTS` edges and set claim status. They previously did
  nothing, so `support_claim()` looked successful while leaving the claim
  unsupported and the gate failing.

  **Still unprojected:** `report_packaged`, `experiment_dispatched`,
  `case_parked`. They are metadata with no gate consequence today.
- Gate predicates live in `gates/predicates.py` as JSON, evaluated in
  `gates/engine.py`. New leaf forms need both a handler and a `_describe` entry,
  or the trace prints `all` and tells the reviewer nothing.
- Tests assert *properties*, not happy paths. The useful ones prove a refusal, a
  preserved disagreement, or a reproducible verdict.

## Scope discipline

The public repo is `matthew-eth724/clockwork`. Before committing, check that
`.venv/` and `var/` are untracked — the venv is ~90MB and `var/` holds generated
artifacts.

## When you are done

State what you changed, what you ran, and what you did not verify. Do not
summarise at length or re-prove green checks.

## UI

The dashboard is a React SPA in `ui/`, built with Vite to `web/app/` (generated,
untracked) and served by FastAPI with an SPA fallback so `/case/<id>` survives a
hard refresh. The old Jinja templates were removed; do not reintroduce a second
rendering path.

Live updates are incremental by design: the client sends `?after=<seq>` and
receives only new events. Keep it that way — re-fetching the whole log on a timer
would make an idle tab cost the same as an active one.

```bash
cd ui && npm install
npm run dev              # :5173, proxies /api to :8899
npm run build            # must be run before the FastAPI-served UI reflects changes
ui/check-live <case_id>  # proves a live update without reload, in a browser
```

`ui/check-live` appends a real event to the case it checks. Run it against the
demo case only after a reset, or expect the seal barrier to reject a re-run of
`clockwork.demo` on a case that already has sealed orbits.
