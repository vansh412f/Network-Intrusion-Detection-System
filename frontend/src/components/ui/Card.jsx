import { memo } from 'react'

const GLOW_STYLES = {
  blue:   '0 0 24px rgba(59, 130, 246, 0.12)',
  green:  '0 0 24px rgba(16, 185, 129, 0.12)',
  red:    '0 0 24px rgba(239, 68, 68, 0.12)',
  amber:  '0 0 24px rgba(245, 158, 11, 0.12)',
  purple: '0 0 24px rgba(139, 92, 246, 0.12)'
}

function CardInner({ children, className = '', glow, hover = false, style = {} }) {
  return (
    <div
      className={`rounded-xl border ${className}`}
      style={{
        backgroundColor: 'var(--color-bg-card)',
        borderColor:     'var(--color-border-card)',
        boxShadow:       glow ? GLOW_STYLES[glow] : undefined,
        transition:      hover ? 'border-color 200ms ease' : undefined,
        ...style
      }}
      onMouseEnter={hover ? e => {
        e.currentTarget.style.borderColor = 'var(--color-border-hover)'
      } : undefined}
      onMouseLeave={hover ? e => {
        e.currentTarget.style.borderColor = 'var(--color-border-card)'
      } : undefined}
    >
      {children}
    </div>
  )
}

export const Card = memo(CardInner)