import { memo, useRef } from 'react'
import { motion, useAnimate } from 'framer-motion'
import { Lock, Unlock } from 'lucide-react'

function timeAgo(isoString) {
  if (!isoString) return ''
  const seconds = Math.floor((Date.now() - new Date(isoString).getTime()) / 1000)
  if (seconds < 60)  return `${seconds}s ago`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60)  return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24)    return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

function BlocklistItemInner({ entry, onUnblock, isAuthenticated }) {
  const ip        = entry.ip        || 'Unknown'
  const blockedBy = entry.blockedBy || 'System'
  const time      = timeAgo(entry.createdAt)

  const lastClickRef = useRef(0)
  const [scope, animate] = useAnimate()

  const handleUnblockClick = () => {
    const now = Date.now()
    if (now - lastClickRef.current < 1500) return
    lastClickRef.current = now

    if (!isAuthenticated) {
      animate(scope.current, { x: [0, -4, 4, -4, 4, 0] }, { duration: 0.35 })
    }
    onUnblock?.(ip)
  }

  return (
    <div
      className="flex items-center justify-between gap-4 border-b px-4 py-3 transition-colors duration-150 sm:px-5"
      style={{ borderColor: 'rgba(255,255,255,0.04)' }}
      onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-bg-hover)'}
      onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
    >
      <div className="flex min-w-0 flex-1 items-center gap-3">
        <Lock
          size={13}
          strokeWidth={1.75}
          style={{ color: '#f59e0b', flexShrink: 0 }}
          aria-hidden="true"
        />
        <div className="min-w-0">
          <span
            className="font-mono text-sm font-medium"
            style={{ color: 'var(--color-text-primary)' }}
          >
            {ip}
          </span>
          <div
            className="mt-0.5 flex flex-wrap items-center gap-x-2"
            style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}
          >
            <span>
              Blocked by{' '}
              <span style={{ color: 'var(--color-text-secondary)' }}>{blockedBy}</span>
            </span>
            {time && (
              <>
                <span style={{ opacity: 0.4 }}>·</span>
                <span>{time}</span>
              </>
            )}
            {entry.reason && (
              <>
                <span style={{ opacity: 0.4 }}>·</span>
                <span className="truncate max-w-[180px]">{entry.reason}</span>
              </>
            )}
          </div>
        </div>
      </div>

      <motion.button
        ref={scope}
        onClick={handleUnblockClick}
        title={isAuthenticated ? `Unblock ${ip}` : 'Login to unblock IPs'}
        aria-label={isAuthenticated ? `Unblock ${ip}` : 'Login required to unblock IPs'}
        className="flex flex-shrink-0 items-center gap-1.5 rounded-lg border px-3 py-1.5 font-medium transition-colors duration-150"
        style={{
          fontSize:        '11px',
          borderColor:     'var(--color-border-card)',
          backgroundColor: 'transparent',
          color:           'var(--color-text-secondary)'
        }}
        whileHover={{
          borderColor: 'rgba(16,185,129,0.4)',
          color:       '#10b981'
        }}
        whileTap={{ scale: 0.96 }}
      >
        <Unlock size={11} strokeWidth={1.75} aria-hidden="true" />
        Unblock
      </motion.button>
    </div>
  )
}

export const BlocklistItem = memo(BlocklistItemInner)