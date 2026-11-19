// Evidence clock: the append-only event log, newest at the bottom.
//
// New events are appended as they arrive and briefly highlighted, so a live
// session shows activity the way a terminal would, without losing your place.
import { useEffect, useRef } from 'react'

const ORBIT_CLASS = {
  attack: 'o-attack',
  defense: 'o-defense',
  history: 'o-history',
  impact: 'o-impact',
  system: 'o-system',
}

export function EventClock({ events }) {
  const prevLen = useRef(events.length)
  const listRef = useRef(null)
  const freshFrom = useRef(events.length)

  useEffect(() => {
    if (events.length > prevLen.current) {
      freshFrom.current = prevLen.current
      const el = listRef.current
      if (el) {
        // Only follow the tail if the user is already at the bottom.
        const nearBottom =
          el.scrollHeight - el.scrollTop - el.clientHeight < 120
        if (nearBottom) el.scrollTop = el.scrollHeight
      }
      const t = setTimeout(() => {
        freshFrom.current = events.length
      }, 2200)
      prevLen.current = events.length
      return () => clearTimeout(t)
    }
    prevLen.current = events.length
  }, [events.length])

  return (
    <div className="clock" ref={listRef}>
      {events.map((e, i) => {
        const isNew = i >= freshFrom.current && i >= events.length - 40
        return (
          <div
            key={e.seq}
            className={`ev ${ORBIT_CLASS[e.orbit] ?? 'o-system'} ${
              isNew ? 'ev-new' : ''
            }`}
          >
            <span className="seq">#{e.seq}</span>
            <span className="type">{e.type}</span>
            <span className="actor">{e.actor}</span>
            <span className="tick">
              {e.type.startsWith('orbit_sealed')
                ? '\u25c6'
                : e.type.startsWith('gate_')
                  ? '\u2726'
                  : ''}
            </span>
          </div>
        )
      })}
      {events.length === 0 && <p className="muted">no events yet</p>}
    </div>
  )
}
