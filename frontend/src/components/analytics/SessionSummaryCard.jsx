import { motion } from 'framer-motion'
import { ShieldAlert } from 'lucide-react'
import { Card } from '../ui/Card'

const fadeUp = {
  hidden: { opacity: 0, y: 18 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } }
}

export function SessionSummaryCard({ alertCount, uniqueIPCount, blockedCount, geoCount }) {
  return (
    <motion.div variants={fadeUp}>
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert
            size={13}
            strokeWidth={1.75}
            style={{ color: 'var(--color-primary-blue)' }}
          />
          <h3
            className="text-xs font-semibold uppercase"
            style={{ letterSpacing: '0.08em', color: 'var(--color-text-muted)' }}
          >
            Session Summary
          </h3>
        </div>

        <div className="space-y-2.5">
          {[
            {
              label:  'Total Threats',
              value:  alertCount,
              color:  'var(--color-primary-blue)'
            },
            {
              label:  'Unique IPs',
              value:  uniqueIPCount,
              color:  '#10b981'
            },
            {
              label:  'Blocked',
              value:  blockedCount,
              color:  '#f59e0b'
            },
            {
              label:  'Geo-Mapped',
              value:  geoCount,
              color:  '#a78bfa'
            }
          ].map(({ label, value, color }) => (
            <div
              key={label}
              className="flex items-center justify-between"
            >
              <span style={{ fontSize: '12px', color: 'var(--color-text-secondary)' }}>
                {label}
              </span>
              <span style={{ fontSize: '15px', fontWeight: 700, color }}>
                {value}
              </span>
            </div>
          ))}

          {alertCount > 0 && (
            <div className="mt-1">
              <div
                className="overflow-hidden rounded-full"
                style={{ height: '4px', backgroundColor: 'rgba(255,255,255,0.06)' }}
              >
                <motion.div
                  style={{
                    height:          '100%',
                    borderRadius:    '9999px',
                    backgroundColor: '#f59e0b'
                  }}
                  initial={{ width: 0 }}
                  animate={{ width: `${(blockedCount / alertCount) * 100}%` }}
                  transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1] }}
                />
              </div>
              <p style={{ fontSize: '9px', color: 'var(--color-text-muted)', marginTop: '3px' }}>
                {alertCount > 0
                  ? `${((blockedCount / alertCount) * 100).toFixed(1)}% of threats blocked`
                  : ''
                }
              </p>
            </div>
          )}
        </div>
      </Card>
    </motion.div>
  )
}
