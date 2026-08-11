import { motion } from 'framer-motion'
import { Globe } from 'lucide-react'
import { Card } from '../ui/Card'

const SEVERITY_COLORS = {
  LOW:      '#64748b',
  MEDIUM:   '#f59e0b',
  HIGH:     '#fb923c',
  CRITICAL: '#ef4444'
}

export function TopIPsTable({ topIPs, alerts, ipsRef, ipsInView }) {
  return (
    <motion.div
      ref={ipsRef}
      initial={{ opacity: 0, y: 18 }}
      animate={ipsInView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5 }}
    >
      <Card className="overflow-hidden">
        <div
          className="border-b px-5 py-3"
          style={{ borderColor: 'var(--color-border-card)' }}
        >
          <h2
            className="text-sm font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Top Attacking IPs
          </h2>
        </div>

        {topIPs.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-center">
            <Globe
              size={26}
              strokeWidth={1.25}
              style={{ color: 'var(--color-text-muted)', opacity: 0.4 }}
            />
            <p style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
              No IP data yet
            </p>
          </div>
        ) : (
          <div className="divide-y" style={{ '--tw-divide-opacity': 0.5 }}>
            {topIPs.map(({ ip, count }, index) => {
              const maxCount  = topIPs[0].count
              const pct       = Math.round((count / maxCount) * 100)
              const alert     = alerts.find(a => a.source_ip === ip)
              const severity  = alert?.severity || 'LOW'
              const geo       = alert?.geo

              return (
                <motion.div
                  key={ip}
                  initial={{ opacity: 0, x: -8 }}
                  animate={ipsInView ? { opacity: 1, x: 0 } : {}}
                  transition={{ duration: 0.35, delay: index * 0.04 }}
                  className="flex items-center gap-4 px-5 py-2.5 transition-colors"
                  style={{ borderColor: 'rgba(255,255,255,0.04)' }}
                  onMouseEnter={e => e.currentTarget.style.backgroundColor = 'var(--color-bg-hover)'}
                  onMouseLeave={e => e.currentTarget.style.backgroundColor = 'transparent'}
                >
                  <span
                    style={{
                      width:      '20px',
                      textAlign:  'center',
                      fontSize:   '10px',
                      fontWeight: 700,
                      color:      'var(--color-text-muted)'
                    }}
                  >
                    #{index + 1}
                  </span>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span
                        className="font-mono truncate"
                        style={{ fontSize: '12px', color: 'var(--color-text-primary)' }}
                      >
                        {ip}
                      </span>
                      {geo && (
                        <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', flexShrink: 0 }}>
                          {geo.flag} {geo.country}
                        </span>
                      )}
                    </div>
                    <div className="mt-1 flex items-center gap-2">
                      <div
                        className="flex-1 overflow-hidden rounded-full"
                        style={{ height: '3px', backgroundColor: 'rgba(255,255,255,0.06)' }}
                      >
                        <motion.div
                          style={{
                            height:          '100%',
                            borderRadius:    '9999px',
                            backgroundColor: SEVERITY_COLORS[severity]
                          }}
                          initial={{ width: 0 }}
                          animate={ipsInView ? { width: `${pct}%` } : {}}
                          transition={{ duration: 0.8, delay: index * 0.05, ease: [0.16, 1, 0.3, 1] }}
                        />
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-shrink-0">
                    <span
                      className="rounded-full px-1.5 py-0.5"
                      style={{
                        fontSize:        '9px',
                        fontWeight:      700,
                        backgroundColor: `${SEVERITY_COLORS[severity]}18`,
                        color:           SEVERITY_COLORS[severity]
                      }}
                    >
                      {severity}
                    </span>
                    <span
                      style={{
                        fontSize:   '11px',
                        fontWeight: 600,
                        color:      'var(--color-text-muted)',
                        minWidth:   '48px',
                        textAlign:  'right'
                      }}
                    >
                      {count} alert{count !== 1 ? 's' : ''}
                    </span>
                  </div>
                </motion.div>
              )
            })}
          </div>
        )}
      </Card>
    </motion.div>
  )
}
