// ============================================================
// src/components/ThreatChart.jsx
// Live line chart showing threat confidence over time
// Uses Recharts library
// ============================================================

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine
} from 'recharts'

// Custom tooltip that appears when hovering over the chart
function CustomTooltip({ active, payload, label }) {
  if (active && payload && payload.length) {
    return (
      <div className="bg-slate-700 border border-slate-600
                      rounded-lg px-3 py-2 shadow-xl">
        <p className="text-slate-300 text-xs">{label}</p>
        <p className="text-red-400 font-bold">
          {payload[0].value}% confidence
        </p>
      </div>
    )
  }
  return null
}

// Custom Y-axis tick formatter
// Shows "Threshold" at 80%, percentage for others
function formatYAxis(value) {
  if (value === 80) {
    return '⚠ 80%'
  }
  return `${value}%`
}

export function ThreatChart({ alerts }) {

  // Transform alerts into chart data
  // Take last 20 alerts, reverse so oldest is on left
  const chartData = alerts
    .slice(0, 20)
    .reverse()
    .map((alert, index) => ({
      name:  new Date(alert.createdAt).toLocaleTimeString(),
      conf:  Math.round(alert.probability * 10) / 10,
      ip:    alert.source_ip
    }))

  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">

      {/* Chart Header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-white font-semibold">
            Live Threat Confidence
          </h2>
          <p className="text-slate-400 text-xs mt-0.5">
            Last 20 detections — only shows threats ≥80%
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-3 h-0.5 bg-red-400" />
          <span className="text-slate-400 text-xs">Confidence %</span>
        </div>
      </div>

      {/* Chart */}
      {chartData.length === 0 ? (
        // Empty state
        <div className="h-48 flex items-center justify-center">
          <p className="text-slate-500 text-sm">
            Waiting for threat detections...
          </p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <LineChart data={chartData}>

            <CartesianGrid
              strokeDasharray="3 3"
              stroke="#334155"
            />

            <XAxis
              dataKey="name"
              stroke="#64748b"
              tick={{ fontSize: 11, fill: '#64748b' }}
            />

            <YAxis
              domain={[75, 100]}
              ticks={[75, 80, 85, 90, 95, 100]}
              stroke="#64748b"
              tick={{ fontSize: 11, fill: '#64748b' }}
              tickFormatter={formatYAxis}
              width={50}
            />

            <Tooltip content={<CustomTooltip />} />

            {/* Red reference line at 80% threshold */}
            <ReferenceLine
              y={80}
              stroke="#ef4444"
              strokeDasharray="4 4"
              strokeWidth={2}
            />

            <Line
              type="monotone"
              dataKey="conf"
              stroke="#f87171"
              strokeWidth={2}
              dot={{ fill: '#f87171', r: 3 }}
              activeDot={{ r: 5, fill: '#ef4444' }}
            />

          </LineChart>
        </ResponsiveContainer>
      )}

    </div>
  )
}