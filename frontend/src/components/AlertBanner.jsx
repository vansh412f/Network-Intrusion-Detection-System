// ============================================================
// src/components/AlertBanner.jsx
// Shows a red banner below header when a new threat arrives
// Auto-dismisses after 4 seconds
// ============================================================

import { useState, useEffect } from 'react'

export function AlertBanner({ latestAlert }) {
  const [visible, setVisible] = useState(false)
  const [currentAlert, setCurrentAlert] = useState(null)

  useEffect(() => {
    // Every time latestAlert changes, show the banner
    if (latestAlert) {
      setCurrentAlert(latestAlert)
      setVisible(true)

      // Auto hide after 4 seconds
      const timer = setTimeout(() => {
        setVisible(false)
      }, 4000)

      return () => clearTimeout(timer)
    }
  }, [latestAlert])

  if (!visible || !currentAlert) return null

  return (
    <div className="bg-red-600 text-white px-6 py-3
                    flex items-center justify-between
                    shadow-lg animate-pulse">

      {/* Left — Alert info */}
      <div className="flex items-center gap-3 max-w-7xl mx-auto w-full justify-between">
        <div className="flex items-center gap-3">
          <span className="text-xl">🚨</span>
          <div>
            <p className="font-bold text-sm">
              THREAT DETECTED
            </p>
            <p className="text-xs text-red-100">
              Source IP: {currentAlert.source_ip} |
              Confidence: {Math.round(currentAlert.probability * 10) / 10}% |
              Type: {currentAlert.threat_type}
            </p>
          </div>
        </div>

        {/* Right — Dismiss button */}
        <button
          onClick={() => setVisible(false)}
          className="text-red-200 hover:text-white
                     text-lg font-bold ml-4"
        >
          ✕
        </button>
      </div>

    </div>
  )
}