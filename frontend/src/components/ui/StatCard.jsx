import { useEffect, memo } from 'react'
import { motion, useMotionValue, useTransform, animate } from 'framer-motion'

const ACCENT_STYLES = {
  blue: {
    gradient: 'rgba(59, 130, 246, 0.07)',
    icon:     '#3b82f6',
    border:   'rgba(59, 130, 246, 0.18)',
    strip:    '#3b82f6'
  },
  green: {
    gradient: 'rgba(16, 185, 129, 0.07)',
    icon:     '#10b981',
    border:   'rgba(16, 185, 129, 0.18)',
    strip:    '#10b981'
  },
  red: {
    gradient: 'rgba(239, 68, 68, 0.07)',
    icon:     '#ef4444',
    border:   'rgba(239, 68, 68, 0.18)',
    strip:    '#ef4444'
  },
  amber: {
    gradient: 'rgba(245, 158, 11, 0.07)',
    icon:     '#f59e0b',
    border:   'rgba(245, 158, 11, 0.18)',
    strip:    '#f59e0b'
  },
  purple: {
    gradient: 'rgba(139, 92, 246, 0.07)',
    icon:     '#a78bfa',
    border:   'rgba(139, 92, 246, 0.18)',
    strip:    '#a78bfa'
  },
  slate: {
    gradient: 'rgba(100, 116, 139, 0.07)',
    icon:     '#64748b',
    border:   'rgba(100, 116, 139, 0.18)',
    strip:    '#64748b'
  }
}

function StatCardInner({ icon: Icon, label, value, unit = '', subtext, accent = 'blue' }) {
  const style      = ACCENT_STYLES[accent] || ACCENT_STYLES.blue
  const isNumber   = typeof value === 'number'

  // Framer Motion count-up
  const mv         = useMotionValue(0)
  const display    = useTransform(mv, v => {
    const rounded = Math.round(v * 10) / 10
    return Number.isInteger(rounded) ? Math.round(rounded) : rounded
  })

  useEffect(() => {
    if (!isNumber || isNaN(value)) return
    const controls = animate(mv, value, {
      duration: 0.85,
      ease:     [0.16, 1, 0.3, 1]
    })
    return controls.stop
  }, [value, isNumber, mv])

  return (
    <motion.div
      className="relative overflow-hidden rounded-xl p-2.5"
      style={{
        border:     `1px solid ${style.border}`,
        background: `linear-gradient(135deg, ${style.gradient} 0%, transparent 55%), var(--color-bg-card)`
      }}
      whileHover={{ scale: 1.015 }}
      transition={{ type: 'spring', stiffness: 350, damping: 25 }}
    >
      {/* Bottom color strip (Reference C pattern) */}
      <div
        style={{
          position:        'absolute',
          bottom:          0,
          left:            0,
          right:           0,
          height:          '2px',
          borderRadius:    '0 0 12px 12px',
          backgroundColor: style.strip,
          opacity:         0.65
        }}
      />

      <div className="flex items-center gap-2.5">
        {Icon && (
          <div
            className="flex h-7 w-7 flex-shrink-0 items-center justify-center rounded-lg"
            style={{
              backgroundColor: style.gradient,
              border:          `1px solid ${style.border}`
            }}
          >
            <Icon size={14} strokeWidth={1.75} style={{ color: style.icon }} aria-hidden="true" />
          </div>
        )}

        <div className="min-w-0 flex-1">
          <p
            className="truncate font-semibold uppercase"
            style={{ fontSize: '9px', letterSpacing: '0.09em', color: 'var(--color-text-muted)' }}
          >
            {label}
          </p>
          <p className="text-base font-bold leading-tight flex items-baseline gap-1 truncate" style={{ color: 'var(--color-text-primary)' }}>
            {isNumber
              ? <motion.span>{display}</motion.span>
              : value
            }
            {unit && (
              <span className="text-xs font-normal" style={{ color: 'var(--color-text-secondary)' }}>
                {unit}
              </span>
            )}
            {subtext && (
              <span className="text-[10px] font-normal" style={{ color: 'var(--color-text-muted)' }}>
                {subtext}
              </span>
            )}
          </p>
        </div>
      </div>
    </motion.div>
  )
}

export const StatCard = memo(StatCardInner)