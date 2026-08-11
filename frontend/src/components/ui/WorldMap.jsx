import { useMemo, useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  ComposableMap, Geographies, Geography,
  Marker, Line, ZoomableGroup
} from 'react-simple-maps'
import { WORLD_GEOJSON } from '@/lib/use-world-data'
import { SEVERITY_COLORS } from '@/lib/severityColors'

const TARGET_LAT = 37.0902
const TARGET_LNG = -95.7129

// ── Tooltip rendered as HTML overlay via absolute positioning ─────────────────
// Cannot use framer-motion divs inside SVG — tooltip is portalled outside the map

function DotTooltip({ alert, x, y }) {
  const color = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.LOW

  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92, y: 4 }}
      animate={{ opacity: 1, scale: 1, y: 0 }}
      exit={{ opacity: 0, scale: 0.92, y: 4 }}
      transition={{ duration: 0.15 }}
      style={{
        position:        'fixed',
        left:            x,
        top:             y,
        transform:       'translate(-50%, calc(-100% - 14px))',
        zIndex:          100,
        pointerEvents:   'none',
        backgroundColor: '#0f172a',
        border:          `1px solid ${color}50`,
        borderRadius:    '10px',
        padding:         '10px 14px',
        minWidth:        '210px',
        boxShadow:       `0 12px 40px rgba(0,0,0,0.6), 0 0 0 1px ${color}15`
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
        <span style={{ fontSize: '16px' }}>{alert.geo?.flag || '🌐'}</span>
        <div>
          <p style={{ fontSize: '12px', fontWeight: 700, color: '#f8fafc', lineHeight: 1.2 }}>
            {alert.geo?.country || 'Unknown'}
            {alert.geo?.city ? ` · ${alert.geo.city}` : ''}
          </p>
          {alert.geo?.isp && (
            <p style={{ fontSize: '10px', color: '#64748b', marginTop: '1px' }}>{alert.geo.isp}</p>
          )}
        </div>
      </div>

      <div style={{ height: '1px', backgroundColor: '#1e293b', margin: '6px 0' }} />

      <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
        {[
          { label: 'IP',         value: alert.source_ip,                               mono: true },
          { label: 'Severity',   value: alert.severity,                                color: color },
          { label: 'Confidence', value: `${Math.round(alert.probability * 10) / 10}%`, mono: true },
          { label: 'Type',       value: alert.threat_type || 'DDoS' },
          { label: 'Status',     value: alert.blocked ? '⛔ Blocked' : '✓ Active',     color: alert.blocked ? '#ef4444' : '#10b981' }
        ].map(({ label, value, color: c, mono }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: '10px', color: '#64748b' }}>{label}</span>
            <span style={{
              fontSize:   '11px',
              fontWeight: c ? 700 : 400,
              fontFamily: mono ? 'monospace' : 'inherit',
              color:      c || '#e2e8f0'
            }}>
              {value}
            </span>
          </div>
        ))}
      </div>
    </motion.div>
  )
}

// ── SVG threat dot — renders correctly inside react-simple-maps SVG context ───

function ThreatDotSVG({ alert, index, isHovered, onMouseEnter, onMouseLeave }) {
  const color  = SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.LOW
  const r      = alert.severity === 'CRITICAL' ? 7 : alert.severity === 'HIGH' ? 6 : 5
  const isCrit = alert.severity === 'CRITICAL'
  const isRecent = Date.now() - new Date(alert.createdAt).getTime() < 2 * 60 * 1000

  return (
    <g
      onMouseEnter={onMouseEnter}
      onMouseLeave={onMouseLeave}
      style={{ cursor: 'pointer' }}
    >
      {/* Pulse ring — recent or critical */}
      {(isRecent || isCrit) && (
        <circle r={r + 2} fill="none" stroke={color} strokeWidth={1.5} opacity={0}>
          <animate
            attributeName="r"
            from={r + 2}
            to={r * 3}
            dur="2s"
            begin={`${index * 0.3}s`}
            repeatCount="indefinite"
          />
          <animate
            attributeName="opacity"
            from={0.7}
            to={0}
            dur="2s"
            begin={`${index * 0.3}s`}
            repeatCount="indefinite"
          />
        </circle>
      )}

      {/* Second pulse for critical */}
      {isCrit && (
        <circle r={r + 2} fill="none" stroke={color} strokeWidth={1} opacity={0}>
          <animate
            attributeName="r"
            from={r + 2}
            to={r * 2.5}
            dur="2s"
            begin={`${index * 0.3 + 0.7}s`}
            repeatCount="indefinite"
          />
          <animate
            attributeName="opacity"
            from={0.5}
            to={0}
            dur="2s"
            begin={`${index * 0.3 + 0.7}s`}
            repeatCount="indefinite"
          />
        </circle>
      )}

      {/* Main dot */}
      <circle
        r={r}
        fill={color}
        opacity={isHovered ? 1 : 0.9}
        filter={`drop-shadow(0 0 ${isHovered ? 8 : 4}px ${color})`}
      />

      {/* Blocked indicator */}
      {alert.blocked && (
        <text
          textAnchor="middle"
          dominantBaseline="central"
          fontSize={r * 1.4}
          fill="white"
          fontWeight="bold"
          style={{ pointerEvents: 'none', userSelect: 'none' }}
        >
          ×
        </text>
      )}
    </g>
  )
}

// ── Main WorldMap component ───────────────────────────────────────────────────

export function WorldMap({ alerts = [], className = '' }) {
  const [hoveredId,  setHoveredId]  = useState(null)
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 })
  const [zoom,       setZoom]       = useState(1)

  const plottable = useMemo(() =>
    alerts.filter(a =>
      a.geo?.lat != null &&
      a.geo?.lng != null &&
      !isNaN(a.geo.lat) &&
      !isNaN(a.geo.lng)
    ),
  [alerts])

  const dedupedByIP = useMemo(() => {
    const ipMap = new globalThis.Map()
    plottable.forEach(alert => {
      const existing = ipMap.get(alert.source_ip)
      if (!existing) {
        ipMap.set(alert.source_ip, alert)
      } else {
        const severityOrder = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 }
        if ((severityOrder[alert.severity] || 0) > (severityOrder[existing.severity] || 0)) {
          ipMap.set(alert.source_ip, alert)
        }
      }
    })
    return Array.from(ipMap.values())
  }, [plottable])

  const hoveredAlert = useMemo(
    () => dedupedByIP.find(a => a._id === hoveredId) || null,
    [dedupedByIP, hoveredId]
  )

  const handleMouseEnter = (alert, e) => {
    setHoveredId(alert._id)
    setTooltipPos({ x: e.clientX, y: e.clientY })
  }

  const handleMouseMove = (e) => {
    if (hoveredId) setTooltipPos({ x: e.clientX, y: e.clientY })
  }

  return (
    <div
      className={`relative w-full overflow-hidden rounded-xl border shadow-inner ${className}`}
      style={{
        height:          '420px',
        userSelect:      'none',
        backgroundColor: '#0f172a',
        borderColor:     'var(--color-border-card)'
      }}
      onMouseMove={handleMouseMove}
    >
      <ComposableMap
        projection="geoMercator"
        projectionConfig={{ scale: 130, center: [0, 20] }}
        style={{ width: '100%', height: '100%' }}
      >
        <ZoomableGroup
          zoom={zoom}
          minZoom={1}
          maxZoom={4}
          onMoveEnd={({ zoom: z }) => setZoom(z)}
          translateExtent={[[-100, -100], [900, 600]]}
        >
          {/* Countries */}
          <Geographies geography={WORLD_GEOJSON}>
            {({ geographies }) =>
              geographies.map((geo) => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  fill="#1e3a5f"
                  stroke="#4a7ab5"
                  strokeWidth={0.5}
                  style={{
                    default: { outline: 'none' },
                    hover:   { outline: 'none', fill: '#2a4a6f' },
                    pressed: { outline: 'none' }
                  }}
                />
              ))
            }
          </Geographies>

          {/* Attack arc lines */}
          {dedupedByIP.map((alert) => (
            <Line
              key={`line-${alert._id}`}
              from={[alert.geo.lng, alert.geo.lat]}
              to={[TARGET_LNG, TARGET_LAT]}
              stroke={SEVERITY_COLORS[alert.severity] || SEVERITY_COLORS.LOW}
              strokeWidth={1.5}
              strokeOpacity={0.25}
              strokeDasharray="4 3"
              style={{ pointerEvents: 'none' }}
            />
          ))}

          {/* Target — monitored server (US) */}
          <Marker coordinates={[TARGET_LNG, TARGET_LAT]}>
            <circle r={6} fill="#3b82f6" style={{ filter: 'drop-shadow(0 0 8px #3b82f6)' }} />
            <circle r={6} fill="none" stroke="#3b82f6" strokeWidth={2} opacity={0}>
              <animate attributeName="r"       from={6}   to={20}  dur="2s" repeatCount="indefinite" />
              <animate attributeName="opacity" from={0.8} to={0}   dur="2s" repeatCount="indefinite" />
            </circle>
          </Marker>

          {/* Threat dots */}
          {dedupedByIP.map((alert, i) => (
            <Marker
              key={alert._id}
              coordinates={[alert.geo.lng, alert.geo.lat]}
            >
              <ThreatDotSVG
                alert={alert}
                index={i}
                isHovered={hoveredId === alert._id}
                onMouseEnter={(e) => handleMouseEnter(alert, e)}
                onMouseLeave={() => setHoveredId(null)}
              />
            </Marker>
          ))}
        </ZoomableGroup>
      </ComposableMap>

      {/* Zoom controls */}
      <div
        className="absolute bottom-3 right-3 flex flex-col gap-1"
        style={{ zIndex: 10 }}
      >
        {[
          { label: '+', action: () => setZoom(z => Math.min(z + 0.5, 4)) },
          { label: '−', action: () => setZoom(z => Math.max(z - 0.5, 1)) }
        ].map(({ label, action }) => (
          <button
            key={label}
            onClick={action}
            className="flex h-7 w-7 items-center justify-center rounded-lg border font-bold transition-colors duration-150"
            style={{
              fontSize:        '16px',
              backgroundColor: 'rgba(15,23,42,0.85)',
              borderColor:     'var(--color-border-card)',
              color:           'var(--color-text-secondary)',
              backdropFilter:  'blur(8px)'
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor = 'var(--color-primary-blue)'}
            onMouseLeave={e => e.currentTarget.style.borderColor = 'var(--color-border-card)'}
            aria-label={label === '+' ? 'Zoom in' : 'Zoom out'}
          >
            {label}
          </button>
        ))}
        {zoom > 1 && (
          <button
            onClick={() => setZoom(1)}
            className="flex h-7 w-7 items-center justify-center rounded-lg border transition-colors duration-150"
            style={{
              fontSize:        '9px',
              backgroundColor: 'rgba(15,23,42,0.85)',
              borderColor:     'var(--color-border-card)',
              color:           'var(--color-text-muted)',
              backdropFilter:  'blur(8px)'
            }}
            aria-label="Reset zoom"
          >
            ↺
          </button>
        )}
      </div>

      {/* Tooltip — rendered as fixed overlay, not inside SVG */}
      <AnimatePresence>
        {hoveredAlert && (
          <DotTooltip
            alert={hoveredAlert}
            x={tooltipPos.x}
            y={tooltipPos.y}
          />
        )}
      </AnimatePresence>

      {/* Empty state */}
      {dedupedByIP.length === 0 && (
        <div className="absolute inset-0 flex items-center justify-center pointer-events-none z-10">
          <p
            className="text-xs px-4 py-2 rounded-full border backdrop-blur-sm"
            style={{
              color:           'var(--color-text-muted)',
              backgroundColor: 'rgba(15,23,42,0.8)',
              borderColor:     'var(--color-border-card)'
            }}
          >
            Waiting for geo-enriched threats...
          </p>
        </div>
      )}
    </div>
  )
}