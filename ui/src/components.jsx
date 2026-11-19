// Shared presentation primitives + live-status indicator.

export function Pill({ state, children }) {
  return <span className={`pill ${state ?? ''}`}>{children ?? state}</span>
}

export function StatusDot({ status }) {
  const label = {
    connecting: 'connecting',
    live: 'live',
    idle: 'live',
    paused: 'paused',
    error: 'disconnected',
    reconnecting: 'reconnecting',
  }[status] ?? status
  return (
    <span className={`live-status ${status}`} title={`stream: ${label}`}>
      <span className="live-dot" aria-hidden="true" />
      <span className="live-label">{label}</span>
    </span>
  )
}

export function Section({ title, right, children }) {
  return (
    <section className="card">
      <header className="card-head">
        <h2>{title}</h2>
        {right}
      </header>
      {children}
    </section>
  )
}

export function Empty({ children }) {
  return <p className="muted">{children}</p>
}
