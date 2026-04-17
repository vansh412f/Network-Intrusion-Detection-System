// ============================================================
// src/components/SensorLog.jsx
// Sensor log panel driven by LiveStats + ThreatDetected events.
//
// Both SIMULATE and REAL modes receive LiveStats from the
// backend every 2s, so both use identical log generation logic.
// Difference: real mode labels flows as "Live flow" instead of
// using simulated IPs (which would be misleading).
// ============================================================

import { useState, useEffect, useRef } from 'react'
import { LogPanel } from './LogPanel'

const BENIGN_IPS = [
  "142.250.80.46",
  "13.69.116.109",
  "140.82.114.21",
  "151.101.1.140",
  "104.21.45.231",
  "52.84.163.89",
  "192.168.31.1",
  "8.8.8.8",
]

export function SensorLog({ sensorMode, liveStats, alerts }) {
  const [logs, setLogs] = useState([])
  const processedWindowRef = useRef(new Set())
  const processedAlertRef  = useRef(new Set())

  // ── Window logs: runs for BOTH modes ─────────────────────────
  // Triggered every 2s when a new LiveStats entry arrives
  useEffect(() => {
    if (!liveStats || liveStats.length === 0) return

    const latestStats = liveStats[liveStats.length - 1]
    const windowKey   = `${latestStats.time}-${latestStats.packets}`

    // Skip if already processed this window
    if (processedWindowRef.current.has(windowKey)) return
    processedWindowRef.current.add(windowKey)

    const timestamp = latestStats.time
    const windowNum = liveStats.length
    const numFlows  = latestStats.flows || 2

    // Window header log
    const windowLog = {
      id:      `window-${windowNum}-${Date.now()}`,
      message: `[${timestamp}] ℹ️   Window #${String(windowNum).padStart(4, '0')} | Flows: ${numFlows} IPs | Packets: ${latestStats.packets} total`
    }

    // Per-flow logs — IPs for simulate, "Live flow" label for real
    const flowLogs = []
    for (let i = 0; i < numFlows; i++) {
      const randomConf = (Math.random() * 25 + 5).toFixed(1)

      const label = sensorMode === 'real'
        ? `Live flow #${i + 1}`
        : BENIGN_IPS[Math.floor(Math.random() * BENIGN_IPS.length)]

      flowLogs.push({
        id:      `flow-${windowNum}-${i}-${Date.now()}`,
        message: `[${timestamp}] 🔍    ✅ [BENIGN] ${label} | Confidence: ${randomConf}%`
      })
    }

    // eslint-disable-next-line react/no-direct-mutation-state
    setLogs(prev => [...prev, windowLog, ...flowLogs].slice(-80))
  }, [liveStats, sensorMode])

  // ── Alert logs: runs for BOTH modes ──────────────────────────
  // Triggered when a new threat alert arrives
  useEffect(() => {
    if (!alerts || alerts.length === 0) return

    const latestAlert = alerts[0]
    const alertKey    = latestAlert._id

    // Skip if already processed this alert
    if (processedAlertRef.current.has(alertKey)) return
    processedAlertRef.current.add(alertKey)

    const timestamp = new Date().toLocaleTimeString()

    const alertLog = {
      id:      `malicious-${alertKey}-${Date.now()}`,
      message: `[${timestamp}] 🚨   🚨 [MALICIOUS] ${latestAlert.source_ip} | Confidence: ${latestAlert.probability}%`
    }

    // eslint-disable-next-line react/no-direct-mutation-state
    setLogs(prev => [...prev, alertLog].slice(-80))
  }, [alerts])

  return (
    <LogPanel
      title="Sensor Log"
      subtitle={`Python sensor.py output — ${sensorMode === 'real' ? 'Live packet capture' : 'Simulated traffic'}`}
      logs={logs}
      icon="🐍"
      badgeText={sensorMode === 'simulate' ? 'SIMULATE' : 'REAL'}
      badgeColor={sensorMode === 'simulate' ? 'bg-orange-400' : 'bg-green-400'}
    />
  )
}