import { useEffect, useRef, useState, memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

const LOG_COLORS = {
  window:     '#3b82f6',
  benign:     '#10b981',
  malicious:  '#ef4444',
  save:       '#a78bfa',
  emit:       '#22d3ee',
  connect:    '#10b981',
  disconnect: '#ef4444',
  health:     '#3b82f6',
  error:      '#fb923c',
  info:       'var(--color-text-muted)',
  default:    'var(--color-text-secondary)'
}

const LOG_WEIGHTS = {
  malicious: '600',
  default:   '400'
}

// macOS traffic-light dots
function TrafficLights() {
  return (
    <div className="flex items-center gap-1.5">
      {['#ef4444', '#f59e0b', '#10b981'].map((color, i) => (
        <div
          key={i}
          style={{
            width:           9,
            height:          9,
            borderRadius:    '50%',
            backgroundColor: color,
            opacity:         0.85
          }}
        />
      ))}
    </div>
  )
}

function LogPanelInner({
  title,
  subtitle,
  logs,
  icon: Icon,
  badgeText,
  badgeColor,
  badgeTextColor,
  metrics = []        // [{ label: 'FLOWS', value: '2,401' }, ...]
}) {
  const scrollRef     = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const prevLengthRef = useRef(0)

  useEffect(() => {
    if (!scrollRef.current) return
    if (autoScroll && logs.length !== prevLengthRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
    prevLengthRef.current = logs.length
  }, [logs, autoScroll])

  const handleScroll = () => {
    if (!scrollRef.current) return
    const { scrollTop, scrollHeight, clientHeight } = scrollRef.current
    setAutoScroll(scrollHeight - scrollTop - clientHeight < 50)
  }

  const getColor  = (type) => LOG_COLORS[type]  || LOG_COLORS.default
  const getWeight = (type) => LOG_WEIGHTS[type]  || LOG_WEIGHTS.default

  // Protocol URL for the fake address bar
  const protocol = title === 'Sensor Log' ? 'nids://sensor-log' : 'nids://backend-log'

  return (
    <div
      className="flex flex-col overflow-hidden rounded-xl border"
      style={{
        borderColor:     'var(--color-border-card)',
        backgroundColor: 'var(--color-bg-card)'
      }}
    >
      {/* ── macOS Window Chrome ── */}
      <div
        style={{
          backgroundColor: 'rgba(255,255,255,0.03)',
          borderBottom:    '1px solid var(--color-border-card)',
          padding:         '8px 12px',
          display:         'flex',
          alignItems:      'center',
          gap:             '10px'
        }}
      >
        <TrafficLights />

        {/* Fake URL bar */}
        <div
          style={{
            flex:            1,
            display:         'flex',
            alignItems:      'center',
            justifyContent:  'center'
          }}
        >
          <span
            className="font-mono"
            style={{
              fontSize:  '10px',
              color:     'var(--color-text-muted)',
              opacity:   0.7,
              letterSpacing: '0.02em'
            }}
          >
            {protocol}
          </span>
        </div>

        {/* Live status indicator */}
        <div className="flex items-center gap-1.5">
          <motion.div
            style={{
              width:           6,
              height:          6,
              borderRadius:    '50%',
              backgroundColor: badgeColor
            }}
            animate={{ opacity: [0.5, 1, 0.5] }}
            transition={{ duration: 1.5, repeat: Infinity, ease: 'easeInOut' }}
          />
          <span
            className="font-mono"
            style={{
              fontSize:      '9px',
              fontWeight:    600,
              color:         badgeTextColor || badgeColor,
              letterSpacing: '0.08em'
            }}
          >
            {badgeText}
          </span>
        </div>
      </div>

      {/* ── Sub-header metrics strip ── */}
      {metrics.length > 0 && (
        <div
          style={{
            display:         'flex',
            alignItems:      'center',
            borderBottom:    '1px solid var(--color-border-card)',
            backgroundColor: 'rgba(255,255,255,0.015)',
            padding:         '5px 12px',
            gap:             0
          }}
        >
          {metrics.map(({ label, value }, i) => (
            <div
              key={label}
              style={{
                display:     'flex',
                alignItems:  'center',
                gap:         '6px',
                flex:        1,
                borderRight: i < metrics.length - 1 ? '1px solid var(--color-border-card)' : 'none',
                paddingRight: i < metrics.length - 1 ? '12px' : 0,
                paddingLeft:  i > 0 ? '12px' : 0
              }}
            >
              <span
                className="font-mono"
                style={{
                  fontSize:      '8px',
                  letterSpacing: '0.1em',
                  color:         'var(--color-text-muted)',
                  textTransform: 'uppercase',
                  whiteSpace:    'nowrap'
                }}
              >
                {label}
              </span>
              <span
                className="font-mono"
                style={{
                  fontSize:   '11px',
                  fontWeight: 700,
                  color:      'var(--color-text-primary)'
                }}
              >
                {value}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* ── Title row (compact, below chrome) ── */}
      <div
        className="flex items-center justify-between border-b px-3 py-1.5"
        style={{ borderColor: 'var(--color-border-card)' }}
      >
        <div className="flex items-center gap-2">
          {Icon && (
            <Icon
              size={12}
              strokeWidth={1.75}
              style={{ color: 'var(--color-text-muted)' }}
              aria-hidden="true"
            />
          )}
          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
            {title}
          </span>
          <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
            —
          </span>
          <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
            {subtitle}
          </span>
        </div>

        {/* Log count badge — fixed padding */}
        <span
          className="font-mono"
          style={{
            fontSize:        '10px',
            fontWeight:      600,
            color:           'var(--color-text-muted)',
            backgroundColor: 'rgba(255,255,255,0.04)',
            border:          '1px solid var(--color-border-card)',
            borderRadius:    '6px',
            padding:         '2px 10px',   // ← was px-1.5 py-0.5, now spacious
            minWidth:        '32px',
            textAlign:       'center'
          }}
        >
          {logs.length}
        </span>
      </div>

      {/* ── Log body ── */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto"
        style={{
          maxHeight:          '160px',
          backgroundColor:    'var(--color-bg-page)',
          padding:            '8px 10px 4px',
          overscrollBehavior: 'contain'
        }}
      >
        {logs.length === 0 ? (
          <p className="font-mono" style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
            Waiting for data...
          </p>
        ) : (
          <AnimatePresence initial={false}>
            {logs.map((log) => (
              <motion.div
                key={log.id}
                initial={{ opacity: 0, y: 3 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.15 }}
                className="font-mono py-px"
                style={{
                  fontSize:   '11px',
                  lineHeight: '1.55',
                  color:      getColor(log.type),
                  fontWeight: getWeight(log.type)
                }}
              >
                {log.message}
              </motion.div>
            ))}
          </AnimatePresence>
        )}
      </div>

      {/* ── Shell prompt line (always visible at bottom) ── */}
      <div
        style={{
          backgroundColor: 'var(--color-bg-page)',
          borderTop:       '1px solid var(--color-border-card)',
          padding:         '4px 10px 6px'
        }}
      >
        <span className="font-mono" style={{ fontSize: '11px', color: '#10b981' }}>
          root@nids-soc:~${' '}
        </span>
        <span className="font-mono" style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
          monitor --stream
        </span>
        <span
          className="font-mono animate-cursor-blink"
          style={{ fontSize: '11px', color: '#10b981', marginLeft: '2px' }}
        >
          ▊
        </span>
      </div>

      {/* ── Jump to latest button ── */}
      <AnimatePresence>
        {!autoScroll && logs.length > 0 && (
          <motion.button
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{    opacity: 0 }}
            onClick={() => {
              if (scrollRef.current) {
                scrollRef.current.scrollTop = scrollRef.current.scrollHeight
                setAutoScroll(true)
              }
            }}
            className="border-t py-1 text-center transition-colors duration-150 w-full"
            style={{
              fontSize:        '10px',
              color:           'var(--color-primary-blue)',
              borderColor:     'var(--color-border-card)',
              backgroundColor: 'transparent'
            }}
            onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-bg-hover)'}
            onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
          >
            ↓ Jump to latest
          </motion.button>
        )}
      </AnimatePresence>
    </div>
  )
}

export const LogPanel = memo(LogPanelInner)