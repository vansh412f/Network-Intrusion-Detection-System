import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'
import { Card } from '../ui/Card'

const SEVERITY_COLORS = {
  LOW:      '#64748b',
  MEDIUM:   '#f59e0b',
  HIGH:     '#fb923c',
  CRITICAL: '#ef4444'
}

export function SeverityDonutChart({ data, hasData }) {
  return (
    <Card className="p-4">
      <h2
        className="mb-2 text-sm font-semibold"
        style={{ color: 'var(--color-text-primary)' }}
      >
        Severity Distribution
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
          <PieChart>
            <Pie
              data={data.filter(d => d.value > 0)}
              cx="50%"
              cy="50%"
              innerRadius={42}
              outerRadius={68}
              paddingAngle={3}
              dataKey="value"
            >
              {data.filter(d => d.value > 0).map(entry => (
                <Cell
                  key={entry.name}
                  fill={SEVERITY_COLORS[entry.name]}
                  stroke="transparent"
                />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: 'var(--color-bg-card)',
                border:          '1px solid var(--color-border-card)',
                borderRadius:    '8px',
                fontSize:        '12px'
              }}
            />
            <Legend
              formatter={v => (
                <span style={{ color: 'var(--color-text-secondary)', fontSize: '11px' }}>
                  {v}
                </span>
              )}
            />
          </PieChart>
        </ResponsiveContainer>
      )}
    </Card>
  )
}
