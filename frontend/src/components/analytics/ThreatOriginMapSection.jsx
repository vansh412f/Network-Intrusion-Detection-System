import { Globe } from 'lucide-react'
import { Card } from '../ui/Card'
import { WorldMap } from '../ui/WorldMap'

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const SEVERITY_COLORS = {
  LOW:      '#64748b',
  MEDIUM:   '#f59e0b',
  HIGH:     '#fb923c',
  CRITICAL: '#ef4444'
}

export function ThreatOriginMapSection({ alerts, geoCount }) {
  return (
    <Card className="overflow-hidden">
      <div
        className="flex items-center justify-between border-b px-4 py-2.5"
        style={{ borderColor: 'var(--color-border-card)' }}
      >
        <div className="flex items-center gap-2">
          <Globe
            size={14}
            strokeWidth={1.75}
            style={{ color: 'var(--color-primary-blue)' }}
            aria-hidden="true"
          />
          <h2
            className="text-sm font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Threat Origin Map
          </h2>
          {geoCount > 0 && (
            <span
              className="rounded-full px-2 py-0.5"
              style={{
                fontSize:        '10px',
                backgroundColor: 'rgba(59,130,246,0.12)',
                border:          '1px solid rgba(59,130,246,0.2)',
                color:           'var(--color-primary-blue)'
              }}
            >
              {geoCount} mapped
            </span>
          )}
        </div>

        <div className="hidden sm:flex items-center gap-4">
          {SEVERITY_ORDER.map(sev => (
            <div key={sev} className="flex items-center gap-1.5">
              <div
                style={{
                  width:           7,
                  height:          7,
                  borderRadius:    '50%',
                  backgroundColor: SEVERITY_COLORS[sev]
                }}
              />
              <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
                {sev}
              </span>
            </div>
          ))}
          <div className="flex items-center gap-1.5">
            <span style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>
              × = Blocked
            </span>
          </div>
        </div>
      </div>

      <div style={{ backgroundColor: 'var(--color-bg-page)', padding: '6px' }}>
        <WorldMap alerts={alerts} />
      </div>
    </Card>
  )
}
