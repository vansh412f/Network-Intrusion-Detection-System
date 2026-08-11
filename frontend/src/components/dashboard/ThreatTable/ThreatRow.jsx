import { memo, useRef } from 'react'
import { motion, useAnimate } from 'framer-motion'
import { Lock, ShieldOff, Ban } from 'lucide-react'
import { SeverityBadge } from './SeverityBadge'
import { Badge } from '../../ui/Badge'

function formatTime(isoString) {
  if (!isoString) return '—'
  return new Date(isoString).toLocaleTimeString()
}

function ConfidenceCell({ value }) {
  const pct        = Math.round(value * 10) / 10
  const barWidth   = Math.min(pct, 100)
  const barColor   =
    pct >= 99 ? '#ef4444' :
    pct >= 95 ? '#fb923c' :
    pct >= 85 ? '#f59e0b' :
                '#64748b'

  return (
    <div className="flex items-center gap-2">
      <span
        className="font-mono text-xs font-medium tabular-nums"
        style={{ color: barColor, minWidth: '42px' }}
      >
        {pct}%
      </span>
      <div
        className="h-1 w-8 overflow-hidden rounded-full flex-shrink-0"
        style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}
      >
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${barWidth}%`, backgroundColor: barColor }}
        />
      </div>
    </div>
  )
}

function ThreatRowInner({ alert, onBlockIP, isAuthenticated, direction = 1, index = 0, skipAnim = false }) {
  const isBlocked = alert.blocked
  const isManual  = alert.threat_type === 'MANUAL'
  const ipDisplay = alert.source_ip || 'Unknown'

  const lastClickRef = useRef(0)
  const [scope, animate] = useAnimate()

  const handleBlockClick = () => {
  const now = Date.now()
  if (now - lastClickRef.current < 1500) return
  lastClickRef.current = now

  if (!isAuthenticated) {
    animate(scope.current, { x: [0, -4, 4, -4, 4, 0] }, { duration: 0.35 })
  }
  onBlockIP?.(alert.source_ip)
}

  const initialProps = skipAnim ? false : { opacity: 0, x: direction * 20 }
  const animateProps = { opacity: 1, x: 0 }
  const transitionProps = { duration: 0.2, delay: index * 0.04 }

  return (
    <motion.tr
      initial={initialProps}
      animate={animateProps}
      transition={transitionProps}
      className="border-b transition-colors duration-150"
      style={{ borderColor: 'rgba(255,255,255,0.04)' }}
      onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-bg-hover)'}
      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
    >
      <td
        className="whitespace-nowrap px-4 py-2.5 font-mono text-left"
        style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}
      >
        {formatTime(alert.createdAt)}
      </td>

      <td className="whitespace-nowrap px-4 py-2.5 text-left">
        <div className="flex items-center gap-1.5">
          <span
            className="font-mono text-xs"
            style={{
              color:          isBlocked ? 'var(--color-text-muted)' : 'var(--color-text-primary)',
              textDecoration: isBlocked ? 'line-through' : 'none'
            }}
          >
            {ipDisplay}
          </span>
          {isBlocked && (
            <Lock
              size={10}
              strokeWidth={2}
              style={{ color: 'var(--color-text-muted)', flexShrink: 0 }}
              aria-label="IP is blocked"
            />
          )}
        </div>
{!isManual && alert.geo?.country && (
  <p
    className="mt-0.5 truncate max-w-[160px] flex items-center gap-1.5"
    style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}
  >
    <span>{alert.geo.flag || '🌐'}</span>
    <span>{alert.geo.country} ({alert.geo.countryCode || 'N/A'})</span>
  </p>
)}
      </td>

      <td className="whitespace-nowrap px-4 py-2.5 text-left">
        <Badge variant={isManual ? 'manual' : 'ddos'} size="xs">
          {alert.threat_type || 'DDoS'}
        </Badge>
      </td>

      <td className="whitespace-nowrap px-4 py-2.5 text-left">
        <SeverityBadge severity={alert.severity} />
      </td>

      <td className="whitespace-nowrap px-4 py-2.5 text-left">
        <ConfidenceCell value={alert.probability} />
      </td>

      <td className="whitespace-nowrap px-4 py-2.5 text-right">
        {isManual ? (
          <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>—</span>
        ) : isBlocked ? (
          <div className="inline-flex items-center gap-1" style={{ color: 'var(--color-text-muted)' }}>
            <ShieldOff size={11} strokeWidth={1.75} aria-hidden="true" />
            <span style={{ fontSize: '11px' }}>Blocked</span>
          </div>
        ) : (
          <motion.button
  ref={scope}
  onClick={handleBlockClick}
  title={isAuthenticated ? `Block ${alert.source_ip}` : 'Login to block IPs'}
  aria-label={`Block ${alert.source_ip}`}
  className="inline-flex items-center gap-1 rounded-lg border px-2 py-1 font-medium transition-colors duration-150"
  style={{
    fontSize:        '11px',
    backgroundColor: 'rgba(239, 68, 68, 0.12)',
    borderColor:     'rgba(239, 68, 68, 0.35)',
    color:           '#ef4444'
  }}
  whileHover={{ scale: 1.04, backgroundColor: 'rgba(239, 68, 68, 0.22)', borderColor: 'rgba(239, 68, 68, 0.6)' }}
  whileTap={{ scale: 0.96 }}
>
  <Ban size={12} strokeWidth={1.75} />
  <span>Block</span>
</motion.button>
        )}
      </td>
    </motion.tr>
  )
}

export const ThreatRow = memo(ThreatRowInner)