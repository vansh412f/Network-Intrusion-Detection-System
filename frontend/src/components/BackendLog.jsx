/**
 * ============================================================
 * src/components/BackendLog.jsx
 * Backend log panel showing Node.js server activity
 * 
 * Shows:
 *   - Connection/disconnection events
 *   - Alert receipts and MongoDB saves
 *   - Socket.io broadcasts
 *   - Periodic health checks (simulate mode)
 * ============================================================
 */

import { useState, useEffect, useRef } from 'react'
import { LogPanel } from './LogPanel'

export function BackendLog({ isConnected, alerts, sensorMode }) {
  const [logs, setLogs] = useState([])
  const processedAlertRef = useRef(new Set())
  const connectionStateRef = useRef(null)

  // ── Connection status changes ───────────────────────────────
  useEffect(() => {
    const timestamp = new Date().toLocaleTimeString()

    if (isConnected && connectionStateRef.current !== 'connected') {
      connectionStateRef.current = 'connected'
      setLogs(prev => [...prev, {
        id: `connect-${Date.now()}`,
        message: `[${timestamp}] ✅   [Socket.io] Connected`
      }].slice(-50))
    } else if (!isConnected && connectionStateRef.current !== 'disconnected') {
      connectionStateRef.current = 'disconnected'
      setLogs(prev => [...prev, {
        id: `disconnect-${Date.now()}`,
        message: `[${timestamp}] ❌   [Socket.io] Disconnected`
      }].slice(-50))
    }
  }, [isConnected])

  // ── Alert received → MongoDB save → Socket.io broadcast ────
  useEffect(() => {
    if (!alerts || alerts.length === 0) return

    const latestAlert = alerts[0]
    const alertKey = latestAlert._id

    // Skip if already logged this alert
    if (processedAlertRef.current.has(alertKey)) return

    processedAlertRef.current.add(alertKey)

    const timestamp = new Date().toLocaleTimeString()

    const newLogs = [
      {
        id: `alert-rx-${alertKey}`,
        message: `[${timestamp}] 🚨   [Alert] Threat received | IP: ${latestAlert.source_ip} | Conf: ${latestAlert.probability}%`
      },
      {
        id: `alert-save-${alertKey}`,
        message: `[${timestamp}] 📦   [MongoDB] Saved alert | ID: ${alertKey?.slice(-8) || 'unknown'}`
      },
      {
        id: `alert-emit-${alertKey}`,
        message: `[${timestamp}] 📡   [Socket.io] Emitted → ThreatDetected`
      }
    ]

    setLogs(prev => [...prev, ...newLogs].slice(-50))
  }, [alerts])

  // ── Periodic backend health simulation (simulate mode only) ──
  useEffect(() => {
    if (sensorMode !== 'simulate') return

    const interval = setInterval(() => {
      const timestamp = new Date().toLocaleTimeString()
      const randomEvent = Math.random()

      let newLog = null

      if (randomEvent < 0.4) {
        newLog = {
          id: `health-stats-${Date.now()}`,
          message: `[${timestamp}] 📊   [Stats] LiveStats received from sensor`
        }
      } else if (randomEvent < 0.7) {
        newLog = {
          id: `health-check-${Date.now()}`,
          message: `[${timestamp}] 💚   [Health] System healthy | Connected: 1 | Alerts: ${Math.floor(Math.random() * 10)}`
        }
      } else {
        newLog = {
          id: `health-db-${Date.now()}`,
          message: `[${timestamp}] 🗄️    [MongoDB] Atlas connection active`
        }
      }

      if (newLog) {
        setLogs(prev => [...prev, newLog].slice(-50))
      }
    }, 5000) // Every 5 seconds

    return () => clearInterval(interval)
  }, [sensorMode])

  return (
    <LogPanel
      title="Backend Log"
      subtitle={`Node.js server output — ${isConnected ? 'Live' : 'Disconnected'}`}
      logs={logs}
      icon="🟢"
      badgeText={isConnected ? 'CONNECTED' : 'OFFLINE'}
      badgeColor={isConnected ? 'bg-green-400' : 'bg-red-400'}
    />
  )
}