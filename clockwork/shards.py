"""Shard placement: 64 logical case shards over one physical database."""
from __future__ import annotations

import hashlib

SHARD_COUNT = 64


def shard_for(case_id: str) -> int:
    """Stable shard assignment. blake2b keeps it independent of Python's hash
    seed so a replay on another machine lands in the same shard."""
    digest = hashlib.blake2b(case_id.encode(), digest_size=8).digest()
    return int.from_bytes(digest, "big") % SHARD_COUNT


def worker_eligible(placement: dict, worker: dict) -> tuple[bool, str]:
    """Execution placement: a worker may only run on shards it can reach and
    for repositories it is allowed to touch."""
    if not placement.get("active", True):
        return False, "shard inactive"
    if placement.get("worker_pool") not in (worker.get("pools") or ["default"]):
        return False, f"worker pool {placement.get('worker_pool')!r} not served"
    required = set(placement.get("repo_need") or [])
    have = set(worker.get("repos") or [])
    if required and not required.issubset(have):
        return False, f"missing repo affinity: {sorted(required - have)}"
    return True, "eligible"
