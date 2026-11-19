// Case list, live: the list re-polls so a newly opened case appears without a
// manual refresh.
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from './api.js'
import { Empty, Pill, Section, StatusDot } from './components.jsx'

export function CaseList() {
  const [cases, setCases] = useState(null)
  const [status, setStatus] = useState('connecting')
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    let timer = null

    const tick = async () => {
      try {
        const data = await api.cases()
        if (!alive) return
        setCases(data.cases)
        setStatus('live')
        setError(null)
      } catch (err) {
        if (!alive) return
        setStatus('error')
        setError(err.message)
      }
    }

    tick()
    timer = setInterval(tick, 4000)

    const onVis = () => {
      if (document.hidden) {
        clearInterval(timer)
        timer = null
        setStatus('paused')
      } else {
        tick()
        if (!timer) timer = setInterval(tick, 4000)
      }
    }
    document.addEventListener('visibilitychange', onVis)

    return () => {
      alive = false
      if (timer) clearInterval(timer)
      document.removeEventListener('visibilitychange', onVis)
    }
  }, [])

  return (
    <main className="shell">
      <header className="topbar">
        <h1>Clockwork Engineering</h1>
        <span className="muted small">
          evidence-gated graph runtime · lite · 64 shards · 12 gates
        </span>
        <span className="spacer" />
        <StatusDot status={status} />
      </header>

      {error && <p className="notice error">{error}</p>}

      <Section title="Cases">
        {cases === null && <Empty>loading…</Empty>}
        {cases?.length === 0 && (
          <Empty>
            No cases yet — run <code>python -m clockwork.demo</code>
          </Empty>
        )}
        {cases && cases.length > 0 && (
          <div className="scroller">
            <table>
              <thead>
                <tr>
                  <th>case</th>
                  <th>title</th>
                  <th>shard</th>
                  <th>status</th>
                  <th>events</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr key={c.case_id}>
                    <td>{c.case_id}</td>
                    <td>{c.title}</td>
                    <td>{c.shard}</td>
                    <td>
                      <Pill
                        state={
                          c.status === 'packaged'
                            ? 'GREEN'
                            : c.status === 'stale'
                              ? 'STALE'
                              : ''
                        }
                      >
                        {c.status}
                      </Pill>
                    </td>
                    <td>{c.events}</td>
                    <td>
                      <Link to={`/case/${encodeURIComponent(c.case_id)}`}>
                        open clock &rarr;
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Section>
    </main>
  )
}
