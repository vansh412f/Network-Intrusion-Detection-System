// ============================================================
// src/components/ThreatTable.jsx
// Fixed height scrollable table showing recent threat alerts
// ============================================================

function formatTime(isoString) {
  if (!isoString) return '—'
  return new Date(isoString).toLocaleTimeString()
}

function ConfidenceBadge({ value }) {
  let color = 'bg-yellow-500/20 text-yellow-400'

  if (value >= 90) {
    color = 'bg-red-500/20 text-red-400'
  } else if (value >= 70) {
    color = 'bg-orange-500/20 text-orange-400'
  }

  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${color}`}>
      {Math.round(value * 10) / 10}%
    </span>
  )
}

export function ThreatTable({ alerts, stats }) {
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700">

      {/* Table Header */}
      <div className="px-5 py-3 border-b border-slate-700
                      flex items-center justify-between">
        <div className="flex items-center gap-2">
          <h2 className="text-white font-semibold">
            Threat Log
          </h2>
          <span className="text-slate-400 text-sm">
            ({stats.total} alerts • {stats.uniqueIPs} unique IPs)
          </span>
        </div>
        {stats.highestConf > 0 && (
          <span className="bg-red-500/20 text-red-400 text-xs
                           font-medium px-2 py-1 rounded-full">
            Max: {stats.highestConf}%
          </span>
        )}
      </div>

      {/* Table — Fixed height with scroll */}
      <div className="h-48 overflow-y-auto">
        <table className="w-full text-sm">

          <thead className="sticky top-0 bg-slate-800">
            <tr className="border-b border-slate-700">
              <th className="text-left text-slate-400 font-medium px-5 py-2">
                Time
              </th>
              <th className="text-left text-slate-400 font-medium px-5 py-2">
                Source IP
              </th>
              <th className="text-left text-slate-400 font-medium px-5 py-2">
                Threat Type
              </th>
              <th className="text-left text-slate-400 font-medium px-5 py-2">
                Confidence
              </th>
            </tr>
          </thead>

          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan={4}
                    className="text-center text-slate-500 py-8">
                  No threats detected yet — sensor is monitoring...
                </td>
              </tr>
            ) : (
              alerts.map((alert, index) => {
                const type = alert.threat_type || 'DDoS'
                const badgeStyle = type === 'Manual-Test'
                  ? 'bg-purple-500/20 text-purple-400'
                  : 'bg-red-500/20 text-red-400'

                return (
                  <tr
                    key={alert._id || index}
                    className="border-b border-slate-700/50 hover:bg-slate-700/30"
                  >
                    <td className="px-5 py-2 text-slate-300 font-mono text-xs">
                      {formatTime(alert.createdAt)}
                    </td>
                    <td className="px-5 py-2 text-white font-mono">
                      {alert.source_ip}
                    </td>
                    <td className="px-5 py-2">
                      <span className={`text-xs px-2 py-0.5 rounded-full ${badgeStyle}`}>
                        {type}
                      </span>
                    </td>
                    <td className="px-5 py-2">
                      <ConfidenceBadge value={alert.probability} />
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>

        </table>
      </div>

    </div>
  )
}