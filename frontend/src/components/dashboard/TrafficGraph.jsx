import { memo, useMemo } from 'react'
import {
  AreaChart, Area, XAxis, YAxis,
  CartesianGrid, Tooltip, ResponsiveContainer
} from 'recharts'
import { Activity } from 'lucide-react'
import { Card } from '../ui/Card'

function CustomTooltip({ active, payload, label }) {
  if (active && payload?.length) {
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
          style={{ fontSize: '13px', color: 'var(--color-live-green)' }}
        >
          {(payload[0].value || 0).toLocaleString()} packets
        </p>
        {payload[1] && (
          <p
            className="font-mono"
            style={{ fontSize: '11px', color: 'var(--color-text-secondary)' }}
          >
            {(payload[1].value || 0).toLocaleString()} flows
          </p>
        )}
      </div>
    )
  }
  return null
}

function TrafficGraphInner({ liveStats, latestPackets }) {
  const formattedPackets = latestPackets ? latestPackets.toLocaleString() : '0'

  const chartData = useMemo(
    () => liveStats.map(s => ({ ...s, packets: s.packets || 0, flows: s.flows || 0 })),
    [liveStats]
  )

  const tickStyle = {
    fontSize:   10,
    fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
    fill:       'var(--color-text-muted)'
  }

  return (
    <Card className="p-5">
      <div className="mb-4 flex items-center justify-between">
        <div>
          <h2
            className="text-sm font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Live Network Traffic
          </h2>
          <p
            className="mt-0.5 font-mono"
            style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}
          >
            {formattedPackets} packets/window · last 2 min
          </p>
        </div>
        <div className="flex items-center gap-1.5">
          <span
            className="relative flex h-2 w-2"
            aria-hidden="true"
          >
            <span
              className="absolute inline-flex h-full w-full rounded-full animate-ping"
              style={{ backgroundColor: 'var(--color-live-green)', opacity: 0.6 }}
            />
            <span
              className="relative inline-flex h-2 w-2 rounded-full"
              style={{ backgroundColor: 'var(--color-live-green)' }}
            />
          </span>
          <span
            className="text-xs font-medium"
            style={{ color: 'var(--color-live-green)' }}
          >
            Live
          </span>
        </div>
      </div>

      {chartData.length === 0 ? (
        <div className="flex h-48 flex-col items-center justify-center gap-3">
          <Activity
            size={24}
            strokeWidth={1.25}
            style={{ color: 'var(--color-text-muted)', opacity: 0.4 }}
            aria-hidden="true"
          />
          <p
            className="text-sm"
            style={{ color: 'var(--color-text-muted)' }}
          >
            Waiting for sensor data...
          </p>
          <p
            style={{ fontSize: '11px', color: 'var(--color-text-muted)', opacity: 0.6 }}
          >
            Render takes ~60s to wake — please wait
          </p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={chartData} margin={{ top: 4, right: 4, bottom: 0, left: 0 }}>
            <defs>
              <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%"  stopColor="#10b981" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#10b981" stopOpacity={0}    />
              </linearGradient>
            </defs>

            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(255,255,255,0.04)"
              vertical={false}
            />

            <XAxis
              dataKey="time"
              stroke="transparent"
              tick={tickStyle}
              interval="preserveStartEnd"
              tickLine={false}
            />

            <YAxis
              stroke="transparent"
              tick={tickStyle}
              width={48}
              tickLine={false}
              tickFormatter={v => v >= 1000 ? `${(v / 1000).toFixed(0)}k` : v}
            />

            <Tooltip
              content={<CustomTooltip />}
              cursor={{ stroke: 'rgba(16,185,129,0.35)', strokeWidth: 1 }}
            />

            <Area
              type="linear"
              dataKey="packets"
              stroke="#10b981"
              strokeWidth={2}
              fill="url(#trafficGrad)"
              dot={{ r: 2, fill: '#10b981', strokeWidth: 0 }}
              activeDot={{ r: 6, fill: '#10b981', stroke: '#fff', strokeWidth: 1 }}
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
    </Card>
  )
}

export const TrafficGraph = memo(TrafficGraphInner)