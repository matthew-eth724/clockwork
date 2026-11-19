"""Structural novelty fingerprints.

Fingerprints are computed from *mechanism components*, never from prose, so two
agents describing the same root cause in different words still collide and an
agent cannot evade duplicate analysis by rewording a claim.

A fingerprint is a Merkle-ish hash over normalised components:

    sink family | authority boundary | data-flow transform | actor precondition

The ``family`` bucket is coarse and drives precedent lookup; the full hash
drives duplicate detection within and across cases.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

_NORMALISE = {
    "sqli": "sqli", "sql-injection": "sqli", "sql_injection": "sqli",
    "oracle-sql": "sqli",
    "ssrf": "ssrf", "server-side-request-forgery": "ssrf",
    "unauth-ssrf": "ssrf",
    "rce": "rce", "code-execution": "rce", "command-injection": "rce",
    "deserialization": "rce", "ssti": "ssti",
    "xss": "xss", "reflected-xss": "xss", "stored-xss": "xss", "dom-xss": "xss",
    "authz": "authz", "idor": "authz", "access-control": "authz",
    "privilege-escalation": "authz", "mass-assignment": "authz",
    "xxe": "xxe",
    "path-traversal": "lfi", "lfi": "lfi", "rfi": "lfi",
    "race-condition": "race", "toctou": "race",
    "reentrancy": "reentrancy",
    "oracle-manipulation": "oracle",
    "precision-loss": "accounting", "rounding": "accounting",
    "accounting-desync": "accounting",
    "replay": "replay", "signature-replay": "replay",
    "leak": "infoleak", "information-disclosure": "infoleak",
}

_KIND_BUCKETS = {
    "authz": "authorization", "sqli": "injection", "xss": "injection",
    "ssti": "injection", "xxe": "injection", "lfi": "injection",
    "rce": "execution", "ssrf": "server-request", "race": "concurrency",
    "reentrancy": "financial", "oracle": "financial", "accounting": "financial",
    "replay": "state", "infoleak": "disclosure",
}


def _norm(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = _NORMALISE.get(s, s)
    s = re.sub(r"[^a-z0-9_.:/-]+", "-", s)
    return s.strip("-") or "unknown"


def components(*, sink: str, authority: str, transform: str = "",
               precondition: str = "", target: str = "") -> dict[str, str]:
    return {
        "sink": _norm(sink),
        "authority": _norm(authority),
        "transform": _norm(transform or "direct"),
        "precondition": _norm(precondition or "none"),
        "target": _norm(target or "generic"),
    }


def compute_fingerprint(comp: dict[str, str]) -> str:
    ordered = "|".join(f"{k}={comp[k]}" for k in
                       ("sink", "authority", "transform", "precondition", "target"))
    return "fp:" + hashlib.sha256(ordered.encode()).hexdigest()[:32]


def coarse_fingerprint(comp: dict[str, str]) -> str:
    return "fp0:" + hashlib.sha256(comp["sink"].encode()).hexdigest()[:16]


def family(comp: dict[str, str]) -> str:
    return _KIND_BUCKETS.get(comp["sink"], "other")


def compare(a: dict[str, str], b: dict[str, str]) -> dict[str, Any]:
    """Component-wise distance. Two findings are duplicates when sink+authority
    match and no distinguishing precondition separates them."""
    same = {k: a.get(k) == b.get(k) for k in a}
    distinguishing = [k for k in ("transform", "precondition", "target")
                      if not same.get(k)]
    # a differing *precondition* separates two otherwise-identical mechanisms
    # (tenant-admin vs anonymous reachability); a differing transform/target
    # alone does not, provided the precondition still matches
    duplicate = bool(same.get("sink") and same.get("authority")
                     and same.get("precondition"))
    return {
        "identical": compute_fingerprint(a) == compute_fingerprint(b),
        "duplicate_likely": bool(duplicate),
        "same": same,
        "distinguishing_components": distinguishing,
        "distance": sum(1 for v in same.values() if not v),
    }
