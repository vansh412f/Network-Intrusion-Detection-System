import { memo, useMemo } from 'react'
import { motion }        from 'framer-motion'
import {
  LineChart, Line, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer,
  ReferenceLine
} from 'recharts'
import { TrendingUp } from 'lucide-react'
import { Card }       from '../ui/Card'


function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div
      className="rounded-lg border px-3 py-2 shadow-xl"
      style={{
        backgroundColor: 'var(--color-bg-elevated)',
        borderColor:     'var(--color-border-card)'
      }}
    >
      <p
        className="font-mono"
        style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}
      >
        {label}
      </p>
      <p
        className="font-mono font-bold"
        style={{ fontSize: '13px', color: 'var(--color-alert-red)' }}
      >
        {payload[0].value}% confidence
      </p>
    </div>
  )
}

// Label positioned BELOW the reference line so it never collides with data
function ReferenceLabel({ viewBox }) {
  if (!viewBox) return null
  return (
    <text
      x={viewBox.x + 5}
      y={viewBox.y + 14}
      fill="rgba(239,68,68,0.50)"
      fontSize={9}
      fontFamily="'JetBrains Mono', 'Fira Code', monospace"
    >
      Alert threshold — 80%
    </text>
  )
}

function ThreatChartInner({ alerts }) {
  const chartData = useMemo(() =>
    alerts
      .slice(0, 20)
      .reverse()
      .map(alert => ({
        name: new Date(alert.createdAt).toLocaleTimeString(),
        conf: Math.round(alert.probability * 10) / 10,
        ip:   alert.source_ip
      })),
  [alerts])

  const tickStyle = {
    fontSize:   10,
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fill:       'var(--color-text-muted)'
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0  }}
      transition={{ duration: 0.45, delay: 0.15 }}
    >
      <Card className="p-5">
        <div className="mb-4 flex items-center justify-between">
          <div>
            <h2
              className="text-sm font-semibold"
              style={{ color: 'var(--color-text-primary)' }}
            >
              Threat Confidence
            </h2>
            <p className="mt-0.5" style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
  Last 20 detections
</p>
          </div>
          <div className="flex items-center gap-2">
            <div
              className="h-px w-4 rounded-full"
              style={{ backgroundColor: 'var(--color-alert-red)' }}
            />
            <span style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
              Confidence %
            </span>
          </div>
        </div>

        {chartData.length === 0 ? (
          <div className="flex h-48 flex-col items-center justify-center gap-3">
            <TrendingUp
              size={24}
              strokeWidth={1.25}
              style={{ color: 'var(--color-text-muted)', opacity: 0.4 }}
              aria-hidden="true"
            />
            <p className="text-sm" style={{ color: 'var(--color-text-muted)' }}>
              No threats detected yet...
            </p>
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={200}>
            <LineChart
              data={chartData}
              margin={{ top: 8, right: 8, bottom: 0, left: 0 }}
            >
              <CartesianGrid
                strokeDasharray="3 3"
                stroke="rgba(255,255,255,0.04)"
                vertical={false}
              />
              <XAxis
                dataKey="name"
                stroke="transparent"
                tick={tickStyle}
                interval="preserveStartEnd"
                tickLine={false}
              />
              <YAxis
                domain={[75, 100]}
                ticks={[75, 80, 85, 90, 95, 100]}
                stroke="transparent"
                tick={tickStyle}
                tickFormatter={v => `${v}%`}
                width={36}
                tickLine={false}
              />
              <Tooltip content={<CustomTooltip />} />

              {/* Reference line with label BELOW */}
              <ReferenceLine
                y={80}
                stroke="rgba(239,68,68,0.4)"
                strokeDasharray="4 4"
                strokeWidth={1.5}
                label={<ReferenceLabel />}
              />

              <Line
                type="monotone"
                dataKey="conf"
                stroke="var(--color-alert-red)"
                strokeWidth={2}
                dot={{ fill: 'var(--color-alert-red)', r: 3, strokeWidth: 0 }}
                activeDot={{ r: 5, fill: '#dc2626', strokeWidth: 0 }}
              />
            </LineChart>
          </ResponsiveContainer>
        )}
      </Card>
    </motion.div>
  )
}

export const ThreatChart = memo(ThreatChartInner)