// Clockwork API client + live update stream.
//
// The canonical log is append-only, so "real time" does not mean re-fetching
// everything. It means: poll the newest sequence number, and when it moves,
// fetch only what is new. A 77-event case costs one small request per tick when
// nothing is happening, and one incremental request when something is.

const BASE = import.meta.env.VITE_API_BASE ?? ''

async function getJSON(path, opts) {
  const res = await fetch(BASE + path, opts)
  if (!res.ok) {
    let detail = res.statusText
    try {
      const body = await res.json()
      detail = body.detail ?? detail
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(detail, res.status)
  }
  return res.json()
}

export class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export const api = {
  health: () => getJSON('/api/health'),
  cases: () => getJSON('/api/cases'),
  clock: (caseId) => getJSON(`/api/cases/${encodeURIComponent(caseId)}/clock`),
  graph: (caseId) => getJSON(`/api/cases/${encodeURIComponent(caseId)}/graph`),
  chain: (caseId) => getJSON(`/api/cases/${encodeURIComponent(caseId)}/chain`),
  placement: (caseId) =>
    getJSON(`/api/cases/${encodeURIComponent(caseId)}/placement`),
  report: async (caseId, branch) => {
    const res = await fetch(
      `${BASE}/api/cases/${encodeURIComponent(caseId)}/report/${encodeURIComponent(branch)}`,
    )
    if (!res.ok) {
      let detail = res.statusText
      try {
        detail = (await res.json()).detail ?? detail
      } catch {
        /* ignore */
      }
      throw new ApiError(detail, res.status)
    }
    return {
      markdown: await res.text(),
      hash: res.headers.get('X-Content-Hash'),
      package: res.headers.get('X-Package'),
    }
  },
}

// ---------------------------------------------------------------------------
// Live subscription.
//
// strategy: 'poll'   — interval poll of the clock endpoint (default, works
//                      everywhere, no server changes required)
//          'events'  — Server-Sent Events carrying just the sequence number,
//                      then the same incremental fetch (see /api/cases/{id}/stream)
//
// Both paths converge on the same onData callback, so the UI does not care.
// ---------------------------------------------------------------------------

export function subscribeClock(caseId, onData, onStatus, options = {}) {
  const { intervalMs = 1500, strategy = 'poll' } = options

  let cancelled = false
  let timer = null
  let source = null
  let lastSeq = -1
  let casesPayload = null

  const emit = (payload) => {
    if (cancelled) return
    casesPayload = payload
    lastSeq = payload.upto_seq ?? 0
    onData(payload)
  }

  const reportStatus = (status, extra = {}) => {
    if (!cancelled) onStatus?.({ status, ...extra })
  }

  async function fetchFull() {
    try {
      const data = await api.clock(caseId)
      if (cancelled) return
      emit(data)
      reportStatus('live', { at: Date.now(), mode: 'full' })
    } catch (err) {
      reportStatus('error', { error: err.message })
    }
  }

  // Poll only the tail. With `after=<seq>` the backend returns just the new
  // events plus current branch state, so an idle case costs one tiny response
  // per tick and we never re-download the whole log.
  async function pollOnce() {
    if (cancelled) return
    const first = lastSeq < 0
    const path = first
      ? `/api/cases/${encodeURIComponent(caseId)}/clock`
      : `/api/cases/${encodeURIComponent(caseId)}/clock?after=${lastSeq}`
    try {
      const data = await getJSON(path)
      if (cancelled) return
      if (first || data.changed) {
        emit(first ? data : mergeClock(casesPayload, data))
        reportStatus('live', { at: Date.now(), mode: first ? 'full' : 'delta' })
      } else {
        reportStatus('live', { at: Date.now(), mode: 'idle' })
      }
    } catch (err) {
      reportStatus('error', { error: err.message })
    }
  }

  if (strategy === 'events' && typeof EventSource !== 'undefined') {
    source = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/stream`)
    source.addEventListener('seq', (ev) => {
      const { upto_seq } = JSON.parse(ev.data)
      if (upto_seq > lastSeq) pollOnce()
    })
    source.addEventListener('open', () => {
      if (lastSeq < 0) pollOnce()
    })
    source.addEventListener('error', () => {
      // EventSource retries on its own; surface it, do not kill the stream
      reportStatus('reconnecting', {})
    })
  } else {
    // Kick off immediately, then settle into a steady interval.
    pollOnce()
    timer = setInterval(pollOnce, intervalMs)
  }

  // Pause polling while the tab is hidden: a background tab should not burn
  // requests, and when the user returns the next poll catches up in one delta.
  const onVisibility = () => {
    if (document.hidden) {
      if (timer) clearInterval(timer)
      timer = null
      reportStatus('paused', {})
    } else if (!source) {
      pollOnce()
      if (!timer) timer = setInterval(pollOnce, intervalMs)
    }
  }
  document.addEventListener('visibilitychange', onVisibility)

  return () => {
    cancelled = true
    if (timer) clearInterval(timer)
    if (source) source.close()
    document.removeEventListener('visibilitychange', onVisibility)
  }
}

// Merge a delta clock response into the previously rendered snapshot.
function mergeClock(prev, next) {
  if (!prev) return next
  if (!next.events) return next // full response
  return {
    ...prev,
    ...next,
    events: [...prev.events, ...next.events],
    branches: { ...prev.branches, ...(next.branches ?? {}) },
    seals: { ...prev.seals, ...(next.seals ?? {}) },
    merges: next.merges ?? prev.merges,
  }
}
