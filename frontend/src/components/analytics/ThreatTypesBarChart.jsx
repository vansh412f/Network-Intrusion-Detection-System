import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { Card } from '../ui/Card'

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div
      className="rounded-lg border px-3 py-2 shadow-xl"
      style={{
        backgroundColor: 'var(--color-bg-elevated)',
        borderColor:     'var(--color-border-card)'
      }}
    >
      <p style={{ fontSize: '10px', color: 'var(--color-text-muted)' }}>{label}</p>
      <p style={{ fontSize: '13px', fontWeight: 700, color: 'var(--color-text-primary)' }}>
        {payload[0].value} alerts
      </p>
    </div>
  )
}

export function ThreatTypesBarChart({ data, hasData }) {
  return (
    <Card className="p-4">
      <h2
        className="mb-2 text-sm font-semibold"
        style={{ color: 'var(--color-text-primary)' }}
      >
        Threat Types
      </h2>
      {!hasData ? (
        <div
          className="flex h-40 items-center justify-center text-sm"
          style={{ color: 'var(--color-text-muted)' }}
        >
          No data yet
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={data} barCategoryGap="40%">
            <CartesianGrid
              strokeDasharray="3 3"
              stroke="rgba(255,255,255,0.04)"
              vertical={false}
            />
            <XAxis
              dataKey="name"
              stroke="transparent"
              tick={{ fontSize: 10, fill: 'var(--color-text-muted)' }}
              tickLine={false}
            />
            <YAxis
              stroke="transparent"
              tick={{ fontSize: 10, fill: 'var(--color-text-muted)' }}
              width={28}
              allowDecimals={false}
              tickLine={false}
            />
            <Tooltip content={<ChartTooltip />} />
            <Bar dataKey="value" radius={[6, 6, 0, 0]}>
              {data.map(entry => (
                <Cell
                  key={entry.name}
                  fill={entry.name === 'Manual-Test' ? '#8b5cf6' : '#ef4444'}
                />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      )}
    </Card>
  )
}
