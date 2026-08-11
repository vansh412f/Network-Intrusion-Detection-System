import { motion } from 'framer-motion'

const fadeUp = {
  hidden: { opacity: 0, y: 18 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } }
}

export function AnalyticsStatCard({ icon: Icon, label, value, accent, note }) {
  const colorMap = {
    blue:   { icon: '#3b82f6', border: 'rgba(59,130,246,0.2)',  bg: 'rgba(59,130,246,0.07)',  strip: '#3b82f6' },
    amber:  { icon: '#f59e0b', border: 'rgba(245,158,11,0.2)',  bg: 'rgba(245,158,11,0.07)',  strip: '#f59e0b' },
    red:    { icon: '#ef4444', border: 'rgba(239,68,68,0.2)',   bg: 'rgba(239,68,68,0.07)',   strip: '#ef4444' },
    green:  { icon: '#10b981', border: 'rgba(16,185,129,0.2)',  bg: 'rgba(16,185,129,0.07)',  strip: '#10b981' }
  }
  const c = colorMap[accent] || colorMap.blue

  return (
    <motion.div
      variants={fadeUp}
      className="relative overflow-hidden rounded-xl p-3"
      style={{
        border:     `1px solid ${c.border}`,
        background: `linear-gradient(135deg, ${c.bg} 0%, transparent 60%), var(--color-bg-card)`
      }}
      whileHover={{ scale: 1.015 }}
      transition={{ type: 'spring', stiffness: 350, damping: 25 }}
    >
      <div style={{
        position: 'absolute', bottom: 0, left: 0, right: 0,
        height: '2px', borderRadius: '0 0 12px 12px',
        backgroundColor: c.strip, opacity: 0.6
      }} />

      <div className="flex items-start justify-between gap-2.5">
        <div>
          <p style={{ fontSize: '10px', fontWeight: 600, letterSpacing: '0.08em', color: 'var(--color-text-muted)', textTransform: 'uppercase' }}>
            {label}
          </p>
          <p style={{ fontSize: '22px', fontWeight: 800, color: 'var(--color-text-primary)', lineHeight: 1.1, marginTop: '2px' }}>
            {value}
          </p>
          {note && (
            <p style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
              {note}
            </p>
          )}
        </div>
        <div
          className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg"
          style={{ backgroundColor: c.bg, border: `1px solid ${c.border}` }}
        >
          <Icon size={15} strokeWidth={1.75} style={{ color: c.icon }} />
        </div>
      </div>
    </motion.div>
  )
}
