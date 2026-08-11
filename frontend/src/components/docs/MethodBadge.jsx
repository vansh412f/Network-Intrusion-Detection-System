const METHOD_STYLES = {
  GET:   { bg: 'rgba(16,185,129,0.12)',  border: 'rgba(16,185,129,0.25)',  color: '#10b981' },
  POST:  { bg: 'rgba(59,130,246,0.12)',  border: 'rgba(59,130,246,0.25)',  color: '#3b82f6' },
  PATCH: { bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.25)', color: '#a78bfa' }
}

const AUTH_STYLES = {
  None:   { bg: 'rgba(100,116,139,0.12)', border: 'rgba(100,116,139,0.25)', color: '#94a3b8' },
  JWT:    { bg: 'rgba(245,158,11,0.12)',  border: 'rgba(245,158,11,0.25)',  color: '#f59e0b' },
  Secret: { bg: 'rgba(139,92,246,0.12)', border: 'rgba(139,92,246,0.25)', color: '#a78bfa' }
}

export function MethodBadge({ method }) {
  const s = METHOD_STYLES[method] || METHOD_STYLES.GET
  return (
    <span
      className="rounded px-2 py-0.5 font-mono font-bold"
      style={{ fontSize: '11px', backgroundColor: s.bg, border: `1px solid ${s.border}`, color: s.color }}
    >
      {method}
    </span>
  )
}

export function AuthBadge({ auth }) {
  const s = AUTH_STYLES[auth] || AUTH_STYLES.None
  return (
    <span
      className="rounded-full px-2 py-0.5 font-medium"
      style={{ fontSize: '11px', backgroundColor: s.bg, border: `1px solid ${s.border}`, color: s.color }}
    >
      {auth}
    </span>
  )
}
