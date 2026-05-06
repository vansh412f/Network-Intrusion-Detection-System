// ============================================================
// src/components/TrafficGraph.jsx
// Live area chart showing packets per 2-second window
// ============================================================

import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer
} from 'recharts'

export function TrafficGraph({ liveStats, latestPackets }) {
  
  const formattedPackets = latestPackets 
    ? latestPackets.toLocaleString() 
    : '0'

  return (
    <div className="bg-slate-800 rounded-xl p-5 border border-slate-700">
      
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <h2 className="text-white font-semibold">Live Network Traffic</h2>
          <span className="text-slate-400 text-sm">
            ({formattedPackets} packets)
          </span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
          <span className="text-green-400 text-xs">Live</span>
        </div>
      </div>

      {liveStats.length === 0 ? (
        <div className="h-48 flex flex-col items-center justify-center gap-1">
          <p className="text-slate-500 text-sm">Waiting for sensor data...</p>
          <p className="text-slate-600 text-xs">⏳ Render takes ~60s to wake up — please wait</p>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={liveStats}>
            <defs>
              <linearGradient id="trafficGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
            <XAxis dataKey="time" stroke="#64748b" tick={{ fontSize: 10 }} />
            <YAxis stroke="#64748b" tick={{ fontSize: 10 }} />
            <Tooltip
              contentStyle={{
                backgroundColor: '#1e293b',
                border: '1px solid #334155',
                borderRadius: '8px'
              }}
            />
            <Area
              type="monotone"
              dataKey="packets"
              stroke="#22c55e"
              strokeWidth={2}
              fill="url(#trafficGrad)"
            />
          </AreaChart>
        </ResponsiveContainer>
      )}
      
    </div>
  )
}