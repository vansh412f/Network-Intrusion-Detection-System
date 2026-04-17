/**
 * ============================================================
 * src/components/LogPanel.jsx
 * Generic log panel component with auto-scroll to latest
 * 
 * When new logs arrive, automatically scrolls to bottom
 * so user always sees the latest entry
 * ============================================================
 */

import { useEffect, useRef } from 'react'

export function LogPanel({ title, subtitle, logs, icon, badgeText, badgeColor }) {

  // Ref to the scroll container
  const scrollContainerRef = useRef(null)

  /**
   * Auto-scroll to bottom whenever logs change
   * Runs after DOM updates
   */
  useEffect(() => {
    if (scrollContainerRef.current) {
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight
    }
  }, [logs]) // Trigger on every log change

  /**
   * Get color class for log type
   */
  const getLogStyle = (type) => {
    const styles = {
      'window':     'text-blue-400',
      'benign':     'text-green-400',
      'malicious':  'text-red-400 font-bold',
      'save':       'text-purple-400',
      'emit':       'text-cyan-400',
      'connect':    'text-green-400',
      'disconnect': 'text-red-400',
      'info':       'text-slate-400',
      'error':      'text-orange-400',
    }
    return styles[type] || 'text-slate-300'
  }

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700">

      {/* ── Header ─────────────────────────────────────────────── */}
      <div className="px-4 py-3 border-b border-slate-700 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-lg">{icon}</span>
          <div>
            <h2 className="text-white font-semibold text-sm">{title}</h2>
            <p className="text-slate-400 text-xs">{subtitle}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <div className={`w-2 h-2 rounded-full ${badgeColor} animate-pulse`} />
          <span className={`text-xs ${badgeColor.replace('bg-', 'text-')}`}>
            {badgeText}
          </span>
        </div>
      </div>

      {/* ── Log Container (with auto-scroll) ──────────────────── */}
      <div
        ref={scrollContainerRef}
        className="h-40 overflow-y-auto p-3 font-mono text-xs bg-slate-900/50"
        style={{ overscrollBehavior: 'contain' }}
      >
        {logs.length === 0 ? (
          <p className="text-slate-500">Waiting for data...</p>
        ) : (
          logs.map((log) => (
            <div key={log.id} className={`py-0.5 ${getLogStyle(log.type)}`}>
              {log.message}
            </div>
          ))
        )}
      </div>

    </div>
  )
}