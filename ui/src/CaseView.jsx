// Case dashboard: live event clock + gate rail + seals + kills + graph.
import { useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, subscribeClock } from './api.js'
import { Empty, Pill, Section, StatusDot } from './components.jsx'
import { EventClock } from './EventClock.jsx'
import { GateRail } from './GateRail.jsx'

const ORBITS = ['attack', 'defense', 'history', 'impact']

export function CaseView() {
  const { caseId } = useParams()
  const [clock, setClock] = useState(null)
  const [status, setStatus] = useState('connecting')
  const [lastTick, setLastTick] = useState(null)
  const [graph, setGraph] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    setClock(null)
    setError(null)
    setStatus('connecting')

    const unsubscribe = subscribeClock(
      caseId,
      (payload) => {
        setClock(payload)
        setError(null)
      },
      (s) => {
        setStatus(s.status)
        if (s.at) setLastTick(new Date(s.at))
        if (s.error) setError(s.error)
      },
      { intervalMs: 1500 },
    )

    // The graph payload is heavier and only needed for the node/edge summary.
    let alive = true
    api
      .graph(caseId)
      .then((g) => alive && setGraph(g))
      .catch(() => alive && setGraph(null))

    return () => {
      alive = false
      unsubscribe()
    }
  }, [caseId])

  const branchIds = useMemo(
    () => Object.keys(clock?.branches ?? {}),
    [clock?.branches],
  )

  if (!clock) {
    return (
      <main className="shell">
        <header className="topbar">
          <Link to="/" className="back">
            &larr; cases
          </Link>
          <h1>{caseId}</h1>
          <StatusDot status={status} />
        </header>
        {error ? (
          <p className="notice error">{error}</p>
        ) : (
          <p className="muted">loading…</p>
        )}
      </main>
    )
  }

  return (
    <main className="shell">
      <header className="topbar">
        <Link to="/" className="back">
          &larr; cases
        </Link>
        <h1>{caseId}</h1>
        <Pill state={clock.chain_verified ? 'GREEN' : 'RED'}>
          chain {clock.chain_verified ? 'verified' : 'BROKEN'} · {clock.chain_note}
        </Pill>
        <span className="muted">{clock.events.length} events</span>
        <span className="spacer" />
        <StatusDot status={status} />
        {lastTick && (
          <span className="muted small" title={lastTick.toISOString()}>
            {lastTick.toLocaleTimeString()}
          </span>
        )}
      </header>

      {error && <p className="notice error">{error}</p>}

      <div className="grid">
        <div className="span-8">
          <Section
            title="Evidence clock — append-only case events"
            right={<span className="muted small">seq {clock.upto_seq}</span>}
          >
            <EventClock events={clock.events} />
          </Section>
        </div>

        <div className="span-4">
          <Section title="Orbit seals">
            {ORBITS.map((orbit) => {
              const s = clock.seals?.[orbit]
              return (
                <div key={orbit} className="sealrow">
                  <span className={`orbit-tag o-${orbit}`}>{orbit}</span>
                  {s ? (
                    <span>
                      <b>sealed</b> @seq {s.sealed_seq} · {s.node_ids?.length ?? 0}{' '}
                      nodes · <code>{String(s.seal_hash).slice(7, 19)}…</code>
                    </span>
                  ) : (
                    <span className="muted">unsealed</span>
                  )}
                </div>
              )
            })}
            <h3 className="subhead">Merges</h3>
            {(clock.merges ?? []).length === 0 && (
              <Empty>no merges yet</Empty>
            )}
            {(clock.merges ?? []).map((m, i) => (
              <div key={`${m.orbit}-${i}`} className="sealrow">
                <span className="muted">{m.orbit}</span>
                <span className="muted small">
                  seq {m.seq} · {m.resolution?.agreement?.length ?? 0} agree ·{' '}
                  {m.resolution?.contradictions?.length ?? 0} contradict ·{' '}
                  {m.resolution?.differing_assumptions?.length ?? 0} differing ·{' '}
                  {m.resolution?.source_version_drift?.length ?? 0} drift
                </span>
              </div>
            ))}
          </Section>
        </div>

        {branchIds.map((b) => (
          <div key={b} className="span-6">
            <GateRail
              branchId={b}
              evaluation={clock.branches[b]}
              gateChain={clock.gate_chain}
              gateLabels={clock.gate_labels}
            />
          </div>
        ))}

        {graph && (
          <div className="span-12">
            <Section
              title={`Epistemic graph — ${graph.nodes.length} nodes · ${graph.edges.length} live edges`}
            >
              <div className="kinds">
                {KINDS.map((kind) => (
                  <span key={kind}>
                    {kind}: {graph.nodes.filter((n) => n.kind === kind).length}
                  </span>
                ))}
              </div>
              <div className="scroller">
                <table>
                  <thead>
                    <tr>
                      <th>seq</th>
                      <th>kind</th>
                      <th>orbit</th>
                      <th>node</th>
                      <th>label</th>
                    </tr>
                  </thead>
                  <tbody>
                    {graph.nodes.slice(-40).map((n) => (
                      <tr key={n.id}>
                        <td className="muted">{n.seq}</td>
                        <td>{n.kind}</td>
                        <td className={`orbit-tag o-${n.orbit}`}>{n.orbit}</td>
                        <td>
                          <code>{n.id}</code>
                        </td>
                        <td>{String(n.label).slice(0, 110)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>
          </div>
        )}
      </div>
    </main>
  )
}

const KINDS = [
  'claim',
  'evidence',
  'experiment',
  'control',
  'assumption',
  'impact',
  'fingerprint',
  'artifact',
  'commit',
  'scope_snapshot',
  'precedent',
  'branch',
]
