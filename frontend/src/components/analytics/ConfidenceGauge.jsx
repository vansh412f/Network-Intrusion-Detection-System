import { motion } from 'framer-motion'

export function ConfidenceGauge({ value }) {
  const size        = 100
  const strokeWidth = 8
  const radius      = (size - strokeWidth) / 2
  const circumf     = 2 * Math.PI * radius
  const arcLength   = circumf * 0.75
  const offset      = arcLength - (arcLength * Math.min(value, 100)) / 100

  const color =
    value >= 90 ? '#10b981' :
    value >= 75 ? '#f59e0b' :
                  '#ef4444'

  const label =
    value >= 90 ? 'Excellent' :
    value >= 75 ? 'High'      :
    value >= 60 ? 'Moderate'  : 'Low'

  return (
    <div className="flex flex-col items-center gap-1.5">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          style={{ transform: 'rotate(135deg)' }}
        >
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="rgba(255,255,255,0.06)"
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumf}`}
            strokeLinecap="round"
          />
          <motion.circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={strokeWidth}
            strokeDasharray={`${arcLength} ${circumf}`}
            strokeLinecap="round"
            initial={{ strokeDashoffset: arcLength }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1], delay: 0.3 }}
            style={{ filter: `drop-shadow(0 0 6px ${color}80)` }}
          />
        </svg>
        <div
          style={{
            position:       'absolute',
            inset:          0,
            display:        'flex',
            flexDirection:  'column',
            alignItems:     'center',
            justifyContent: 'center'
          }}
        >
          <span style={{ fontSize: '18px', fontWeight: 800, color, lineHeight: 1 }}>
            {value > 0 ? `${value}%` : '—'}
          </span>
          <span style={{ fontSize: '9px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
            avg conf
          </span>
        </div>
      </div>
      <span
        style={{
          fontSize:   '11px',
          fontWeight: 600,
          color
        }}
      >
        {value > 0 ? label : 'No data'}
      </span>
    </div>
  )
}
