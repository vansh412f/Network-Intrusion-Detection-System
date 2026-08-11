export function ChartScopeFilter({ chartWindow, onChange }) {
  const windows = [
    { id: 'all',    label: 'All Session' },
    { id: 'last25', label: 'Last 25'     },
    { id: 'last10', label: 'Last 10'     }
  ]

  return (
    <div className="flex items-center justify-between gap-3">
      <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
        Chart Data Scope:
      </span>
      <div className="flex items-center gap-1.5">
        {windows.map(w => (
          <button
            key={w.id}
            onClick={() => onChange(w.id)}
            className="rounded-full border px-3 py-1 text-xs font-medium transition-all"
            style={{
              borderColor:     chartWindow === w.id ? 'var(--color-primary-blue)' : 'var(--color-border-card)',
              backgroundColor: chartWindow === w.id ? 'rgba(59,130,246,0.12)' : 'var(--color-bg-card)',
              color:           chartWindow === w.id ? 'var(--color-primary-blue)' : 'var(--color-text-muted)'
            }}
          >
            {w.label}
          </button>
        ))}
      </div>
    </div>
  )
}
