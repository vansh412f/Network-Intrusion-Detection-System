import { motion } from 'framer-motion'

const SEVERITY_COLORS = {
  LOW:      '#64748b',
  MEDIUM:   '#f59e0b',
  HIGH:     '#fb923c',
  CRITICAL: '#ef4444'
}

export function SeverityStackedBar({ data }) {
  const total = data.reduce((s, d) => s + d.value, 0)
  if (total === 0) {
    return (
      <div
        style={{
          height:          '16px',
          borderRadius:    '9999px',
          backgroundColor: 'rgba(255,255,255,0.06)'
        }}
      />
    )
  }

  return (
    <div>
      <div
        className="flex overflow-hidden rounded-full"
        style={{ height: '12px', gap: '2px' }}
      >
        {data.map(({ name, value }) => {
          if (value === 0) return null
          const pct = (value / total) * 100
          return (
            <motion.div
              key={name}
              initial={{ width: 0 }}
              animate={{ width: `${pct}%` }}
              transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
              style={{
                backgroundColor: SEVERITY_COLORS[name],
                height:          '100%',
                minWidth:        '4px'
              }}
              title={`${name}: ${value} (${pct.toFixed(1)}%)`}
            />
          )
        })}
      </div>

      <div className="mt-2.5 flex flex-wrap gap-x-4 gap-y-1">
        {data.map(({ name, value }) => {
          if (value === 0) return null
          const pct = ((value / total) * 100).toFixed(1)
          return (
            <div key={name} className="flex items-center gap-1.5">
              <div
                style={{
                  width:           7,
                  height:          7,
                  borderRadius:    '50%',
                  backgroundColor: SEVERITY_COLORS[name],
                  flexShrink:      0
                }}
              />
              <span style={{ fontSize: '11px', color: 'var(--color-text-secondary)' }}>
                {name}
              </span>
              <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                {pct}%
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
