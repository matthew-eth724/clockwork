-- Clockwork Engineering :: Lite schema
-- Append-only case events are the canonical source of truth.
-- Every derived table below is a *materialized projection* that must be
-- reproducible from the event log alone (see clockwork/projection.py).

CREATE SCHEMA IF NOT EXISTS cw;

-- ---------------------------------------------------------------------------
-- Physical layout: 64 logical shards, all pinned to one physical database.
-- shard_id = hash(case_id) % 64  (stable, in clockwork/shards.py)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.shard_placement (
    shard_id      smallint PRIMARY KEY CHECK (shard_id BETWEEN 0 AND 63),
    physical_dsn  text     NOT NULL,
    region        text     NOT NULL DEFAULT 'local',
    repo_affinity text[]   NOT NULL DEFAULT '{}',   -- artifact replication pins
    worker_pool   text     NOT NULL DEFAULT 'default',
    active        boolean  NOT NULL DEFAULT true
);
INSERT INTO cw.shard_placement (shard_id, physical_dsn)
SELECT g, 'postgresql://clockwork:clockwork@localhost:55432/clockwork'
FROM generate_series(0, 63) AS g
ON CONFLICT DO NOTHING;

-- ---------------------------------------------------------------------------
-- Global actor identity (agents, humans). Authority is granted by events,
-- never by an agent writing to its own row.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.agent (
    agent_id      text PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('human','agent','system')),
    display_name  text NOT NULL,
    -- capabilities are *requested*; the gate graph intersects them with the
    -- standing policy. An agent cannot expand its own capability set.
    requested_caps text[] NOT NULL DEFAULT '{}',
    created_at    timestamptz NOT NULL DEFAULT now()
);

-- ---------------------------------------------------------------------------
-- Canonical log
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.case_event (
    event_id     bigserial PRIMARY KEY,
    case_id      text NOT NULL,
    seq          integer NOT NULL,              -- per-case monotonic sequence
    event_type   text NOT NULL,
    actor_id     text NOT NULL,                 -- producing activity / author
    orbit        text NOT NULL,                 -- attack|defense|history|impact|system
    payload      jsonb NOT NULL DEFAULT '{}',
    -- content hash of (case, seq-1 hash, type, payload, actor) -> tamper evident
    event_hash   text NOT NULL,
    prev_hash    text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    UNIQUE (case_id, seq)
);
CREATE INDEX IF NOT EXISTS case_event_case_seq_idx ON cw.case_event (case_id, seq);
CREATE INDEX IF NOT EXISTS case_event_type_idx ON cw.case_event (event_type);

-- Append-only enforcement: no UPDATE, no DELETE, no TRUNCATE, ever.
CREATE OR REPLACE FUNCTION cw.deny_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'append-only relation %: % is forbidden', TG_TABLE_NAME, TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS case_event_no_update ON cw.case_event;
CREATE TRIGGER case_event_no_update BEFORE UPDATE OR DELETE ON cw.case_event
    FOR EACH ROW EXECUTE FUNCTION cw.deny_mutation();
DROP TRIGGER IF EXISTS case_event_no_truncate ON cw.case_event;
CREATE TRIGGER case_event_no_truncate BEFORE TRUNCATE ON cw.case_event
    FOR EACH STATEMENT EXECUTE FUNCTION cw.deny_mutation();

-- ---------------------------------------------------------------------------
-- Cases and placements
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.case (
    case_id            text PRIMARY KEY,
    shard_id           smallint NOT NULL,
    title              text NOT NULL,
    -- repository affinity: which repos this case owns authoritatively
    repo_ids           text[] NOT NULL DEFAULT '{}',
    scope_snapshot_id  text,
    status             text NOT NULL DEFAULT 'open'
                       CHECK (status IN ('open','stale','packaged','closed')),
    created_seq        integer NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS cw.case_artifact_replica (
    case_id     text NOT NULL REFERENCES cw.case(case_id),
    shard_id    smallint NOT NULL,
    role        text NOT NULL CHECK (role IN ('primary','replica')),
    pinned_repo text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, shard_id)
);

-- ---------------------------------------------------------------------------
-- Epistemic graph nodes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.node (
    node_id     text PRIMARY KEY,              -- globally unique
    case_id     text NOT NULL,
    shard_id    smallint NOT NULL,
    kind        text NOT NULL CHECK (kind IN (
                  'case','branch','claim','assumption','evidence','experiment',
                  'control','artifact','agent','commit','scope_snapshot','impact',
                  'fix','report_section','gate','precedent','kill','fingerprint')),
    label       text NOT NULL,
    branch_id   text,                          -- owning lane for claims/evidence...
    orbit       text NOT NULL DEFAULT 'system',
    status      text NOT NULL DEFAULT 'active',
    attrs       jsonb NOT NULL DEFAULT '{}',
    commit_sha  text,                          -- for events/evidence binding
    source_ref  text,                          -- file:line / url / advisory id
    content_hash text,                         -- artifacts
    created_seq integer NOT NULL,
    updated_seq integer NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Blind-orbit seal bookkeeping: seq at which this node's content was sealed
    sealed_seq  integer,
    sealed_by   text                           -- orbit that produced it
);
CREATE INDEX IF NOT EXISTS node_case_kind_idx ON cw.node (case_id, kind);
CREATE INDEX IF NOT EXISTS node_branch_idx ON cw.node (case_id, branch_id);

CREATE TABLE IF NOT EXISTS cw.edge (
    edge_id     bigserial PRIMARY KEY,
    case_id     text NOT NULL,
    src_id      text NOT NULL,
    rel         text NOT NULL CHECK (rel IN (
                  'SUPPORTS','CONTRADICTS','DEPENDS_ON','TESTS','RULES_OUT',
                  'GENERATED_BY','VERIFIED_BY','BLOCKED_BY','INVALIDATED_BY',
                  'APPLIES_TO_COMMIT','ABSTRACTS_TO','DUPLICATE_OF','FIXED_BY',
                  'INCLUDED_IN')),
    dst_id      text NOT NULL,
    attrs       jsonb NOT NULL DEFAULT '{}',
    produced_by text NOT NULL,
    created_seq integer NOT NULL,
    retired_seq integer,                       -- contradiction-preserving removal
    UNIQUE (case_id, src_id, rel, dst_id)
);
CREATE INDEX IF NOT EXISTS edge_src_idx ON cw.edge (case_id, src_id, rel);
CREATE INDEX IF NOT EXISTS edge_dst_idx ON cw.edge (case_id, dst_id, rel);

-- ---------------------------------------------------------------------------
-- Branches / lanes
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.branch (
    branch_id    text PRIMARY KEY,
    case_id      text NOT NULL,
    parent_id    text,
    git_state    text NOT NULL DEFAULT 'RED'
                 CHECK (git_state IN ('RED','YELLOW','GREEN','STALE')),
    proof_state  text NOT NULL DEFAULT 'none'
                 CHECK (proof_state IN ('none','failing','passing')),
    gate_state   jsonb NOT NULL DEFAULT '{}',   -- gate -> PASSED|FAILED|PENDING
    lane_status  text NOT NULL DEFAULT 'open'
                 CHECK (lane_status IN ('open','parked','merged','killed')),
    merged_into  text,
    commit_range text,                          -- "abc123..def456" or single sha
    repo_id      text,
    created_seq  integer NOT NULL,
    updated_seq  integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Claims
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.claim (
    claim_id     text PRIMARY KEY,
    case_id      text NOT NULL,
    branch_id    text,
    statement    text NOT NULL,
    claim_class  text NOT NULL DEFAULT 'substantive'
                 CHECK (claim_class IN ('substantive','blocking','assumption','scope')),
    confidence   numeric NOT NULL DEFAULT 0.5,
    supported_ev text[] NOT NULL DEFAULT '{}',
    contradicted_ev text[] NOT NULL DEFAULT '{}',
    derived_by   text[] NOT NULL DEFAULT '{}',   -- orbits/activities asserting it
    status       text NOT NULL DEFAULT 'proposed'
                 CHECK (status IN ('proposed','supported','contradicted','retired')),
    created_seq  integer NOT NULL,
    updated_seq  integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Evidence, experiments, controls, artifacts
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.evidence (
    evidence_id   text PRIMARY KEY,
    case_id       text NOT NULL,
    branch_id     text,
    kind          text NOT NULL,     -- control|falsification|proof|metadata|history
    claim_id      text,
    experiment_id text,
    artifact_id   text,
    source_ref    text,
    commit_sha    text,
    generated_by  text NOT NULL,     -- activity / orbit
    verified_by   text[] NOT NULL DEFAULT '{}',
    independently_verified boolean NOT NULL DEFAULT false,
    sealed_seq    integer,           -- set at orbit seal
    created_seq   integer NOT NULL
);

CREATE TABLE IF NOT EXISTS cw.experiment (
    experiment_id text PRIMARY KEY,
    case_id       text NOT NULL,
    branch_id     text,
    command       text NOT NULL,
    environment   text NOT NULL,
    expected_observable text NOT NULL,
    observed      text,
    outcome       text NOT NULL DEFAULT 'pending'
                  CHECK (outcome IN ('pending','pass','fail','error')),
    controls      text[] NOT NULL DEFAULT '{}',
    artifact_hashes text[] NOT NULL DEFAULT '{}',
    commit_sha    text,
    requested_by  text NOT NULL,
    executed_by   text,
    created_seq   integer NOT NULL,
    updated_seq   integer NOT NULL
);

CREATE TABLE IF NOT EXISTS cw.control (
    control_id   text PRIMARY KEY,
    case_id      text NOT NULL,
    branch_id    text,
    kind         text NOT NULL,     -- naive|environment|negative|decoy
    description  text NOT NULL,
    result       text NOT NULL DEFAULT 'pending'
                 CHECK (result IN ('pending','held','broke')),
    artifact_id  text,
    created_seq  integer NOT NULL
);

CREATE TABLE IF NOT EXISTS cw.artifact (
    artifact_id  text PRIMARY KEY,           -- "sha256:<hex>"
    case_id      text NOT NULL,
    media_type   text NOT NULL,
    bytes        bigint NOT NULL,
    storage_path text NOT NULL,
    produced_by  text NOT NULL,
    created_seq  integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Evidence gates
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.gate (
    case_id      text NOT NULL,
    branch_id    text NOT NULL,
    gate_id      text NOT NULL,
    state        text NOT NULL DEFAULT 'PENDING'
                 CHECK (state IN ('PENDING','PASSED','FAILED','BLOCKED')),
    predicate    jsonb NOT NULL,       -- machine-readable transition predicate
    evaluation   jsonb NOT NULL DEFAULT '{}',
    decided_by   text,
    decided_seq  integer,
    PRIMARY KEY (case_id, branch_id, gate_id)
);

-- Gate authorisation ledger: who may have authored critical evidence.
CREATE TABLE IF NOT EXISTS cw.gate_authority (
    gate_id     text PRIMARY KEY,
    requires_independent_verification boolean NOT NULL DEFAULT false,
    critical    boolean NOT NULL DEFAULT false
);

-- ---------------------------------------------------------------------------
-- Kill memory (conditional negative precedent)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.kill_record (
    kill_id            text PRIMARY KEY,
    case_id            text NOT NULL,
    branch_id          text NOT NULL,
    suspected_mechanism text NOT NULL,
    blocking_claim_id  text NOT NULL,
    evidence_ids       text[] NOT NULL DEFAULT '{}',
    repo_id            text,
    commit_range       text,
    invalidation_conditions text[] NOT NULL DEFAULT '{}',
    invalidated_by     text[] NOT NULL DEFAULT '{}',
    author_id          text NOT NULL,
    verifier_id        text,                  -- must differ from author
    verified_seq       integer,
    fingerprint        text NOT NULL,
    created_seq        integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Precedent graph (survives cases)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.precedent (
    precedent_id  text PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN (
                    'vulnerability_pattern','duplicate_family','known_fix',
                    'proof_strategy','negative_precedent')),
    title         text NOT NULL,
    body          jsonb NOT NULL DEFAULT '{}',
    fingerprint   text,
    repo_id       text,
    source_case   text,
    conditions    text[] NOT NULL DEFAULT '{}',
    created_seq   bigint NOT NULL
);

CREATE TABLE IF NOT EXISTS cw.precedent_link (
    link_id      bigserial PRIMARY KEY,
    src_id       text NOT NULL,           -- precedent or node id
    rel          text NOT NULL CHECK (rel IN (
                  'ABSTRACTS_TO','DUPLICATE_OF','FIXED_BY','APPLIES_TO_COMMIT',
                  'DEPENDS_ON','CONTRADICTS')),
    dst_id       text NOT NULL,
    attrs        jsonb NOT NULL DEFAULT '{}',
    created_seq  bigint NOT NULL,
    UNIQUE (src_id, rel, dst_id)
);

-- Novelty fingerprints (structural, not textual)
CREATE TABLE IF NOT EXISTS cw.fingerprint (
    fingerprint   text PRIMARY KEY,
    case_id       text NOT NULL,
    branch_id     text NOT NULL,
    components    jsonb NOT NULL,
    family        text,
    created_seq   integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Blind orbit seals
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.orbit_seal (
    case_id     text NOT NULL,
    orbit       text NOT NULL,
    sealed_seq  integer NOT NULL,
    seal_hash   text NOT NULL,
    node_ids    text[] NOT NULL DEFAULT '{}',
    edge_count  integer NOT NULL DEFAULT 0,
    sealed_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, orbit)
);

CREATE TABLE IF NOT EXISTS cw.orbit_merge (
    merge_id    bigserial PRIMARY KEY,
    case_id     text NOT NULL,
    orbit       text NOT NULL,
    resolution  jsonb NOT NULL,          -- agreement/contradiction/assumption/drift/dispute
    created_seq integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Commits / scope snapshots / impacts / fixes (node metadata, queryable)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.scope_snapshot (
    scope_snapshot_id text PRIMARY KEY,
    case_id           text NOT NULL,
    repo_id           text NOT NULL,
    commit_sha        text NOT NULL,
    scope_manifest    jsonb NOT NULL,
    captured_seq      integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Reports
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.report_section (
    case_id      text NOT NULL,
    branch_id    text NOT NULL,
    section_id   text NOT NULL,
    ordinal      integer NOT NULL,
    heading      text NOT NULL,
    body         text NOT NULL,
    claim_ids    text[] NOT NULL DEFAULT '{}',
    provenance   jsonb NOT NULL DEFAULT '{}',
    PRIMARY KEY (case_id, branch_id, section_id)
);

CREATE TABLE IF NOT EXISTS cw.report_package (
    package_id   text PRIMARY KEY,
    case_id      text NOT NULL,
    branch_id    text NOT NULL,
    content_hash text NOT NULL,
    sections     text[] NOT NULL,
    qc_verdict   jsonb NOT NULL,
    generated_by text NOT NULL,
    created_seq  integer NOT NULL
);

-- ---------------------------------------------------------------------------
-- Derived projections: context packets and cache material are NOT canonical.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cw.context_packet (
    packet_id    text PRIMARY KEY,
    case_id      text NOT NULL,
    agent_id     text NOT NULL,
    role         text NOT NULL,
    node_ids     text[] NOT NULL,
    body         jsonb NOT NULL,
    created_seq  integer NOT NULL,
    cache_only   boolean NOT NULL DEFAULT true
);

CREATE TABLE IF NOT EXISTS cw.summary_cache (
    cache_key    text PRIMARY KEY,
    scope        text NOT NULL,
    text         text NOT NULL,
    derived_from_seq integer NOT NULL,
    -- explicitly disposable: never referenced by any evidence or claim
    disposable   boolean NOT NULL DEFAULT true
);

-- ---------------------------------------------------------------------------
-- Denial-of-authority helpers: agents may not self-expand.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION cw.deny_self_expansion() RETURNS trigger AS $$
BEGIN
    IF NEW.requested_caps <> OLD.requested_caps
       AND current_setting('clockwork.lock_capabilities', true) IS DISTINCT FROM 'off'
    THEN
        RAISE EXCEPTION 'agent % may not expand its own capabilities', OLD.agent_id;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS agent_no_self_expand ON cw.agent;
CREATE TRIGGER agent_no_self_expand BEFORE UPDATE ON cw.agent
    FOR EACH ROW EXECUTE FUNCTION cw.deny_self_expansion();
