// The 12-gate rail for one branch.
//
// Gate state is recomputed server-side on every append, so this re-renders
// whenever the branch payload changes. A gate that flips to PASSED animates once.
import { useEffect, useRef, useState } from 'react'
import { Pill } from './components.jsx'

export function GateRail({ branchId, evaluation, gateChain, gateLabels }) {
  const [justPassed, setJustPassed] = useState(() => new Set())
  const prev = useRef({})

  useEffect(() => {
    const gates = evaluation?.gates ?? {}
    const flipped = []
    for (const [id, g] of Object.entries(gates)) {
      const was = prev.current[id]
      if (was && was !== 'PASSED' && g.state === 'PASSED') flipped.push(id)
      prev.current[id] = g.state
    }
    if (flipped.length) {
      setJustPassed(new Set(flipped))
      const t = setTimeout(() => setJustPassed(new Set()), 2400)
      return () => clearTimeout(t)
    }
  }, [evaluation])

  const state = evaluation?.state ?? '-'
  const nextGate = evaluation?.next_gate

  return (
    <section className="card branch">
      <header className="card-head">
        <h2>
          {branchId} <Pill state={state} />
        </h2>
        <span className="muted small">
          next: <code>{nextGate ?? 'complete'}</code>
        </span>
      </header>
      {(evaluation?.inconsistencies ?? []).length > 0 && (
        <p className="notice error small">
          {evaluation.inconsistencies.map((m) => (
            <span key={m}>{m}</span>
          ))}
        </p>
      )}
      <ol className="rail">
        {gateChain.map((gate) => {
          const st = evaluation?.gates?.[gate]?.state ?? 'PENDING'
          const isNext = gate === nextGate
          return (
            <li
              key={gate}
              className={`gate ${justPassed.has(gate) ? 'gate-passed' : ''} ${
                isNext ? 'gate-next' : ''
              }`}
            >
              <span className={`dot ${st}`} />
              <span className="gate-label">{gateLabels[gate]}</span>
            </li>
          )
        })}
      </ol>
    </section>
  )
}
