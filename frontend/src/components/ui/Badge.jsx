import { memo } from 'react'

const VARIANT_STYLES = {
  low: {
    bg:     'var(--severity-low-bg)',
    border: 'var(--severity-low-border)',
    color:  'var(--severity-low)'
  },
  medium: {
    bg:     'var(--severity-medium-bg)',
    border: 'var(--severity-medium-border)',
    color:  'var(--severity-medium)'
  },
  high: {
    bg:     'var(--severity-high-bg)',
    border: 'var(--severity-high-border)',
    color:  'var(--severity-high)'
  },
  critical: {
    bg:     'var(--severity-critical-bg)',
    border: 'var(--severity-critical-border)',
    color:  'var(--severity-critical)'
  },
  ddos: {
    bg:     'rgba(239, 68, 68, 0.12)',
    border: 'rgba(239, 68, 68, 0.25)',
    color:  '#ef4444'
  },
  manual: {
    bg:     'rgba(139, 92, 246, 0.12)',
    border: 'rgba(139, 92, 246, 0.25)',
    color:  '#a78bfa'
  },
  success: {
    bg:     'rgba(16, 185, 129, 0.12)',
    border: 'rgba(16, 185, 129, 0.25)',
    color:  '#10b981'
  },
  warning: {
    bg:     'rgba(245, 158, 11, 0.12)',
    border: 'rgba(245, 158, 11, 0.25)',
    color:  '#f59e0b'
  },
  neutral: {
    bg:     'rgba(100, 116, 139, 0.12)',
    border: 'rgba(100, 116, 139, 0.25)',
    color:  '#94a3b8'
  },
  primary: {
    bg:     'rgba(59, 130, 246, 0.12)',
    border: 'rgba(59, 130, 246, 0.25)',
    color:  '#3b82f6'
  }
}

const SIZE_STYLES = {
  xs: { fontSize: '10px', padding: '1px 6px', gap: '3px', iconSize: 10 },
  sm: { fontSize: '11px', padding: '2px 7px', gap: '4px', iconSize: 11 },
  md: { fontSize: '12px', padding: '3px 8px', gap: '4px', iconSize: 12 }
}

function BadgeInner({
  children,
  variant = 'neutral',
  size = 'sm',
  icon: Icon,
  pulse = false,
  className = '',
  ariaLabel
}) {
  const style  = VARIANT_STYLES[variant] || VARIANT_STYLES.neutral
  const sizing = SIZE_STYLES[size]       || SIZE_STYLES.sm

  return (
    <span
      className={`inline-flex items-center font-semibold uppercase tracking-[0.07em] rounded-full border ${pulse ? 'animate-pulse' : ''} ${className}`}
      style={{
        backgroundColor: style.bg,
        borderColor:     style.border,
        color:           style.color,
        fontSize:        sizing.fontSize,
        padding:         sizing.padding,
        gap:             sizing.gap
      }}
      aria-label={ariaLabel}
    >
      {Icon && <Icon size={sizing.iconSize} strokeWidth={2} aria-hidden="true" />}
      {children}
    </span>
  )
}

export const Badge = memo(BadgeInner)