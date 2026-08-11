import { Shield } from 'lucide-react'

export function RadarAnimation() {
  return (
    <div className="relative flex items-center justify-center">
      <div className="relative h-64 w-64 sm:h-80 sm:w-80" style={{ animation: 'float 5s ease-in-out infinite' }}>
        {[1, 2, 3, 4].map(i => (
          <div
            key={i}
            className="absolute inset-0 rounded-full border"
            style={{
              borderColor: 'var(--color-primary-blue)',
              opacity:     0.06 + i * 0.04,
              transform:   `scale(${0.25 + i * 0.2})`
            }}
          />
        ))}

        <div
          className="absolute inset-0 rounded-full"
          style={{
            background: 'conic-gradient(from 0deg, transparent 0deg, rgba(59,130,246,0.14) 45deg, transparent 90deg)',
            animation:  'radar-sweep 3s linear infinite'
          }}
        />

        <div className="absolute inset-0 flex items-center justify-center">
          <div className="flex flex-col items-center gap-2">
            <Shield
              size={44}
              strokeWidth={1.25}
              style={{ color: 'var(--color-primary-blue)', filter: 'drop-shadow(0 0 12px rgba(59,130,246,0.5))' }}
            />
            <span
              className="font-mono font-bold uppercase"
              style={{ fontSize: '10px', letterSpacing: '0.28em', color: 'var(--color-primary-blue)' }}
            >
              NIDS SOC
            </span>
          </div>
        </div>

        {[
          { top: '20%', left: '65%', color: 'var(--color-alert-red)',    glow: 'rgba(239,68,68,0.7)',    delay: '0s',   size: 8 },
          { top: '55%', left: '18%', color: 'var(--color-live-green)',   glow: 'rgba(16,185,129,0.6)',   delay: '1s',   size: 6 },
          { top: '72%', left: '70%', color: 'var(--color-warning-amber)',glow: 'rgba(245,158,11,0.6)',   delay: '0.5s', size: 7 }
        ].map(({ top, left, color, glow, delay, size }, i) => (
          <div
            key={i}
            className="absolute rounded-full"
            style={{
              top, left,
              width:           size,
              height:          size,
              backgroundColor: color,
              animation:       `threat-blink ${2 + i * 0.5}s ease-in-out infinite ${delay}`,
              boxShadow:       `0 0 8px ${glow}`
            }}
          />
        ))}
      </div>
    </div>
  )
}
