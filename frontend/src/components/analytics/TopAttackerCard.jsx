import { motion } from 'framer-motion'
import { Target } from 'lucide-react'
import { Card } from '../ui/Card'

const fadeUp = {
  hidden: { opacity: 0, y: 18 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } }
}

const SEVERITY_COLORS = {
  LOW:      '#64748b',
  MEDIUM:   '#f59e0b',
  HIGH:     '#fb923c',
  CRITICAL: '#ef4444'
}

export function TopAttackerCard({ topAttacker }) {
  return (
    <motion.div variants={fadeUp}>
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-3">
          <Target
            size={13}
            strokeWidth={1.75}
            style={{ color: 'var(--color-alert-red)' }}
          />
          <h3
            className="text-xs font-semibold uppercase"
            style={{ letterSpacing: '0.08em', color: 'var(--color-text-muted)' }}
          >
            Top Attacker
          </h3>
        </div>

        {topAttacker ? (
          <div>
            <div className="flex items-start justify-between gap-2">
              <div className="min-w-0">
                <p
                  className="font-mono font-bold truncate"
                  style={{ fontSize: '14px', color: 'var(--color-text-primary)' }}
                >
                  {topAttacker.ip}
                </p>
                {topAttacker.geo && (
                  <p style={{ fontSize: '11px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                    {topAttacker.geo.flag} {topAttacker.geo.city
                      ? `${topAttacker.geo.city}, ${topAttacker.geo.country}`
                      : topAttacker.geo.country
                    }
                  </p>
                )}
              </div>
              <span
                className="rounded-full px-2 py-0.5 flex-shrink-0"
                style={{
                  fontSize:        '10px',
                  fontWeight:      700,
                  backgroundColor: `${SEVERITY_COLORS[topAttacker.severity]}18`,
                  border:          `1px solid ${SEVERITY_COLORS[topAttacker.severity]}40`,
                  color:           SEVERITY_COLORS[topAttacker.severity]
                }}
              >
                {topAttacker.severity}
              </span>
            </div>
            <div
              className="mt-3 rounded-lg p-2.5"
              style={{ backgroundColor: 'rgba(239,68,68,0.06)', border: '1px solid rgba(239,68,68,0.12)' }}
            >
              <p style={{ fontSize: '20px', fontWeight: 800, color: '#ef4444', lineHeight: 1 }}>
                {topAttacker.count}
              </p>
              <p style={{ fontSize: '10px', color: 'var(--color-text-muted)', marginTop: '2px' }}>
                alert{topAttacker.count !== 1 ? 's' : ''} this session
              </p>
            </div>
          </div>
        ) : (
          <div className="flex h-20 items-center justify-center">
            <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
              No attacker data yet
            </p>
          </div>
        )}
      </Card>
    </motion.div>
  )
}
