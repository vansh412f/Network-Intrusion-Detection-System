// ============================================================
// src/components/ThreatTable.jsx
// Threat log — cards on mobile, table on desktop
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
      <div className="px-4 sm:px-5 py-3 border-b border-slate-700
                      flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <h2 className="text-white font-semibold text-sm sm:text-base">
            Threat Log
          </h2>
          <span className="text-slate-400 text-xs truncate">
            ({stats.total} alerts · {stats.uniqueIPs} IPs)
          </span>
        </div>
        {stats.highestConf > 0 && (
          <span className="bg-red-500/20 text-red-400 text-xs
                           font-medium px-2 py-1 rounded-full flex-shrink-0">
            Max: {stats.highestConf}%
          </span>
        )}
      </div>

      {/* ── Mobile: Card list (hidden on md+) ──────────────────── */}
      <div className="md:hidden h-64 overflow-y-auto divide-y divide-slate-700/50">
        {alerts.length === 0 ? (
          <p className="text-center text-slate-500 text-sm py-10">
            No threats detected yet — sensor is monitoring...
          </p>
        ) : (
          alerts.map((alert, index) => {
            const type = alert.threat_type || 'DDoS'
            const badgeStyle = type === 'Manual-Test'
              ? 'bg-purple-500/20 text-purple-400'
              : 'bg-red-500/20 text-red-400'

            return (
              <div
                key={alert._id || index}
                className="px-4 py-3 flex items-start justify-between gap-3 hover:bg-slate-700/30"
              >
                <div className="min-w-0 flex-1">
                  <p className="text-white font-mono text-sm">
                    {alert.source_ip.length > 13
                      ? alert.source_ip.slice(0, 10) + '…'
                      : alert.source_ip}
                  </p>
                  <p className="text-slate-400 font-mono text-xs mt-0.5">{formatTime(alert.createdAt)}</p>
                </div>
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={`text-xs px-2 py-0.5 rounded-full ${badgeStyle}`}>{type}</span>
                  <ConfidenceBadge value={alert.probability} />
                </div>
              </div>
            )
          })
        )}
      </div>

      {/* ── Desktop: Table (hidden on mobile) ──────────────────── */}
      <div className="hidden md:block h-48 overflow-y-auto">
        <table className="w-full text-sm">

          <thead className="sticky top-0 bg-slate-800">
            <tr className="border-b border-slate-700">
              <th className="text-left text-slate-400 font-medium px-5 py-2">Time</th>
              <th className="text-left text-slate-400 font-medium px-5 py-2">Source IP</th>
              <th className="text-left text-slate-400 font-medium px-5 py-2">Threat Type</th>
              <th className="text-left text-slate-400 font-medium px-5 py-2">Confidence</th>
            </tr>
          </thead>

          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan={4} className="text-center text-slate-500 py-8">
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