"""Clockwork HTTP surface: API + evidence-clock dashboard.

Every mutating endpoint goes through :class:`Runtime`, so the same authority
checks apply whether an agent acts over HTTP or in-process.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from .constants import GATE_CHAIN, GATE_LABELS, ORBITS
from .report import UntraceableClaim
from .runtime import AuthorityError, GateError, Runtime

WEB = Path(__file__).resolve().parent.parent / "web"
templates = Jinja2Templates(directory=str(WEB / "templates"))

app = FastAPI(title="Clockwork Engineering", version="0.1.0-lite")
rt = Runtime()


@app.on_event("startup")
def _startup() -> None:
    rt.boot()


def _guard(fn):
    try:
        return fn()
    except (AuthorityError, GateError, ValueError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# --------------------------------------------------------------------- models
class Actor(BaseModel):
    agent_id: str
    kind: str = "agent"
    display_name: str = ""
    caps: list[str] = []


class OpenCase(BaseModel):
    case_id: str
    title: str
    repos: list[str]
    scope_snapshot: dict
    actor: str
    branches: list[dict] | None = None


class Seed(BaseModel):
    case_id: str
    branch_id: str
    actor: str
    suspected_mechanism: str
    repo_id: str
    commit_range: str
    orbit: str = "attack"
    label: str | None = None


class Claim(BaseModel):
    case_id: str
    branch_id: str
    claim_id: str
    statement: str
    actor: str
    orbit: str = "attack"
    claim_class: str = "substantive"
    depends_on: list[str] = []


class Evidence(BaseModel):
    case_id: str
    branch_id: str
    evidence_id: str
    actor: str
    kind: str = "metadata"
    supports: list[str] = []
    contradicts: list[str] = []
    rules_out: list[str] = []
    commit_sha: str | None = None
    source_ref: str | None = None
    label: str | None = None
    orbit: str = "attack"


class ExperimentReq(BaseModel):
    case_id: str
    branch_id: str
    experiment_id: str
    command: str
    environment: str
    expected_observable: str
    actor: str
    tests: list[str] = []
    controls: list[str] = []
    commit_sha: str | None = None
    orbit: str = "attack"


class ExperimentDone(BaseModel):
    case_id: str
    experiment_id: str
    actor: str
    outcome: str
    observed: str
    orbit: str = "attack"


class ControlDone(BaseModel):
    case_id: str
    branch_id: str
    control_id: str
    description: str
    kind: str
    result: str
    actor: str
    tests: list[str] = []
    orbit: str = "defense"


class GateDecision(BaseModel):
    case_id: str
    branch_id: str
    gate_id: str
    actor: str
    decision: str = "pass"
    note: str = ""


class Seal(BaseModel):
    case_id: str
    orbit: str
    actor: str


class Merge(BaseModel):
    case_id: str
    actor: str
    orbits: list[str] = ["attack", "defense"]


class Kill(BaseModel):
    case_id: str
    branch_id: str
    actor: str
    suspected_mechanism: str
    blocking_claim_id: str
    evidence_ids: list[str]
    invalidation_conditions: list[str]
    verifier_id: str
    repo_id: str | None = None
    commit_range: str | None = None


class PacketReq(BaseModel):
    case_id: str
    role: str
    agent_id: str
    branch_id: str
    task: dict | None = None


# ----------------------------------------------------------------------- api
@app.get("/api/health")
def health() -> dict:
    return {"ok": True, "service": "clockwork-engineering", "tier": "lite",
            "shards": 64, "gates": len(GATE_CHAIN), "orbits": list(ORBITS)}


@app.post("/api/actors")
def register_actor(body: Actor) -> dict:
    _guard(lambda: rt.register_agent(body.agent_id, body.kind,
                                     body.display_name or body.agent_id, body.caps))
    return {"registered": body.agent_id}


@app.post("/api/cases")
def open_case(body: OpenCase) -> dict:
    ev = _guard(lambda: rt.open_case(body.case_id, body.title, body.repos,
                                     body.scope_snapshot, body.actor,
                                     body.branches))
    return {"event": ev["seq"], "placement": rt.placement(body.case_id)}


@app.get("/api/cases/{case_id}/graph")
def graph(case_id: str) -> dict:
    facts = _guard(lambda: rt.facts(case_id))
    return {
        "case_id": case_id,
        "upto_seq": facts.upto_seq,
        "nodes": [{"id": n.node_id, "kind": n.kind, "label": n.label,
                   "branch": n.branch_id, "orbit": n.orbit, "seq": n.seq}
                  for n in sorted(facts.nodes.values(), key=lambda x: x.seq)],
        "edges": [{"src": e.src_id, "rel": e.rel, "dst": e.dst_id,
                   "seq": e.seq} for e in facts.live_edges()],
        "seals": facts.seals,
        "merges": facts.merges,
        "kills": list(facts.kills.values()),
    }


@app.get("/api/cases/{case_id}/clock")
def clock(case_id: str) -> dict:
    facts = _guard(lambda: rt.facts(case_id))
    events = rt.store.events(case_id)
    ok, why = rt.store.verify_chain(case_id)
    branches = {}
    for b in facts.of_kind("branch"):
        try:
            branches[b.node_id] = rt.evaluate(case_id, b.node_id)
        except Exception:  # noqa: BLE001 - a branch with no evidence still shows
            branches[b.node_id] = {"state": "-", "gates": {}, "next_gate": None}
    return {"case_id": case_id, "chain_verified": ok, "chain_note": why,
            "events": [{"seq": e["seq"], "type": e["event_type"],
                        "actor": e["actor_id"], "orbit": e["orbit"],
                        "at": e["created_at"].isoformat()} for e in events],
            "seals": facts.seals, "merges": facts.merges,
            "branches": branches, "gate_chain": list(GATE_CHAIN),
            "gate_labels": GATE_LABELS}


@app.get("/api/cases/{case_id}/evaluate/{branch_id}")
def evaluate(case_id: str, branch_id: str) -> dict:
    return _guard(lambda: rt.evaluate(case_id, branch_id))


@app.post("/api/seed")
def seed(body: Seed) -> dict:
    return _guard(lambda: rt.seed_candidate(**body.model_dump()))["payload"]


@app.post("/api/claims")
def claim(body: Claim) -> dict:
    return _guard(lambda: rt.propose_claim(**body.model_dump()))["payload"]


@app.post("/api/evidence")
def evidence(body: Evidence) -> dict:
    return _guard(lambda: rt.add_evidence(**body.model_dump()))["payload"]


@app.post("/api/experiments")
def experiment(body: ExperimentReq) -> dict:
    return _guard(lambda: rt.request_experiment(**body.model_dump()))["payload"]


@app.post("/api/experiments/complete")
def experiment_done(body: ExperimentDone) -> dict:
    return _guard(lambda: rt.complete_experiment(**body.model_dump()))["payload"]


@app.post("/api/controls")
def control(body: ControlDone) -> dict:
    return _guard(lambda: rt.complete_control(**body.model_dump()))["payload"]


@app.post("/api/gates/decide")
def gate_decide(body: GateDecision) -> dict:
    ev = _guard(lambda: rt.decide_gate(**body.model_dump()))
    return {"event": ev["seq"], "decision": body.decision}


@app.post("/api/orbits/seal")
def seal(body: Seal) -> dict:
    return _guard(lambda: rt.seal_orbit(**body.model_dump()))["payload"]


@app.post("/api/orbits/merge")
def merge(body: Merge) -> dict:
    return _guard(lambda: rt.merge_orbits(**body.model_dump()))["payload"]


@app.post("/api/kills")
def kill(body: Kill) -> dict:
    return _guard(lambda: rt.kill_branch(**body.model_dump()))["payload"]


@app.post("/api/context-packet")
def packet(body: PacketReq) -> dict:
    p = _guard(lambda: rt.context_packet(body.case_id, role=body.role,
                                         agent_id=body.agent_id,
                                         branch_id=body.branch_id,
                                         task=body.task))
    return p.to_dict()


@app.get("/api/cases/{case_id}/report/{branch_id}", response_class=PlainTextResponse)
def report(case_id: str, branch_id: str, actor: str = "human:reviewer"):
    def build():
        return rt.build_report(case_id, branch_id, actor)
    try:
        pkg = build()
    except UntraceableClaim as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except (AuthorityError, GateError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return PlainTextResponse(pkg["markdown"],
                             headers={"X-Content-Hash": pkg["content_hash"],
                                      "X-Package": pkg["package_id"]})


@app.get("/api/cases/{case_id}/placement")
def placement(case_id: str) -> dict:
    return _guard(lambda: rt.placement(case_id))


@app.get("/api/cases/{case_id}/chain")
def chain(case_id: str) -> dict:
    ok, why = rt.store.verify_chain(case_id)
    return {"verified": ok, "note": why}


# ----------------------------------------------------------------- dashboard
@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    cases = rt.store.q(
        """SELECT c.case_id, c.title, c.shard_id, c.status,
                  (SELECT count(*) FROM cw.case_event e
                    WHERE e.case_id=c.case_id) AS events
           FROM cw.case c ORDER BY c.created_at DESC""")
    return templates.TemplateResponse(request, "clock.html", {"cases": cases})


@app.get("/case/{case_id}", response_class=HTMLResponse)
def case_view(request: Request, case_id: str):
    data = clock(case_id)
    facts = rt.facts(case_id)
    packets = rt.store.q(
        """SELECT role, agent_id, node_ids, created_seq FROM cw.context_packet
           WHERE case_id=%s ORDER BY created_seq""", (case_id,))
    reports = rt.store.q(
        """SELECT package_id, content_hash, qc_verdict FROM cw.report_package
           WHERE case_id=%s ORDER BY created_seq DESC""", (case_id,))
    return templates.TemplateResponse(request, "case.html", {
        "case_id": case_id, "data": data, "gate_labels": GATE_LABELS,
        "packets": packets, "reports": reports,
        "case_nodes": sorted(facts.nodes.values(), key=lambda n: n.seq),
        "kills": list(facts.kills.values()),
        "edges": facts.live_edges(),
    })
