import { useState, useEffect, useRef, memo } from 'react'
import { Server } from 'lucide-react'
import { LogPanel } from './LogPanel'

const MAX_LOGS = 200

function BackendLogInner({ isConnected, alerts, sensorMode }) {
  const [logs, setLogs]          = useState([])
  const [alertCount, setAlertCount] = useState(0)
  const processedAlertRef        = useRef(new Set())
  const connectionStateRef       = useRef(null)

  useEffect(() => {
    const time = new Date().toLocaleTimeString()

    if (isConnected && connectionStateRef.current !== 'connected') {
      connectionStateRef.current = 'connected'
      setLogs(prev => [...prev, {
        id:      `conn-${Date.now()}`,
        type:    'connect',
        message: `[${time}]   + [Socket.io] Client connected`
      }].slice(-MAX_LOGS))
    } else if (!isConnected && connectionStateRef.current !== 'disconnected') {
      connectionStateRef.current = 'disconnected'
      setLogs(prev => [...prev, {
        id:      `disc-${Date.now()}`,
        type:    'disconnect',
        message: `[${time}]   x [Socket.io] Disconnected`
      }].slice(-MAX_LOGS))
    }
  }, [isConnected])

  useEffect(() => {
    if (!alerts || alerts.length === 0) return

    const latest   = alerts[0]
    const alertKey = latest._id

    if (processedAlertRef.current.has(alertKey)) return
    processedAlertRef.current.add(alertKey)

    if (processedAlertRef.current.size > MAX_LOGS) {
      const first = processedAlertRef.current.values().next().value
      processedAlertRef.current.delete(first)
    }

    setAlertCount(prev => prev + 1)
    const time = new Date().toLocaleTimeString()

    setLogs(prev => [
      ...prev,
      {
        id:      `rx-${alertKey}`,
        type:    'malicious',
        message: `[${time}]   ! [Alert] Threat  ${latest.source_ip}  ${latest.probability}%`
      },
      {
        id:      `save-${alertKey}`,
        type:    'save',
        message: `[${time}]   > [MongoDB] Saved  id: ...${String(alertKey).slice(-6)}`
      },
      {
        id:      `emit-${alertKey}`,
        type:    'emit',
        message: `[${time}]   > [Socket.io] ThreatDetected emitted`
      }
    ].slice(-MAX_LOGS))
  }, [alerts])

  useEffect(() => {
    if (sensorMode !== 'simulate') return

    const interval = setInterval(() => {
      const time = new Date().toLocaleTimeString()
      const rand = Math.random()

      let log
      if (rand < 0.4) {
        log = { id: `stats-${Date.now()}`, type: 'health', message: `[${time}]   > [Stats] LiveStats received from sensor` }
      } else if (rand < 0.7) {
        log = { id: `health-${Date.now()}`, type: 'health', message: `[${time}]   + [Health] System healthy` }
      } else {
        log = { id: `mongo-${Date.now()}`, type: 'health', message: `[${time}]   + [MongoDB] Atlas connection active` }
      }

      setLogs(prev => [...prev, log].slice(-MAX_LOGS))
    }, 5000)

    return () => clearInterval(interval)
  }, [sensorMode])

  const badgeColor = isConnected ? '#10b981' : '#ef4444'
  const badgeText  = isConnected ? 'CONNECTED' : 'OFFLINE'

  const metrics = [
    { label: 'STATUS', value: isConnected ? 'LIVE' : 'OFF' },
    { label: 'ALERTS', value: alertCount.toLocaleString() }
  ]

  return (
    <LogPanel
      title="Backend Log"
      subtitle={`Node.js — ${isConnected ? 'live' : 'disconnected'}`}
      logs={logs}
      icon={Server}
      badgeText={badgeText}
      badgeColor={badgeColor}
      badgeTextColor={badgeColor}
      metrics={metrics}
    />
  )
}

export const BackendLog = memo(BackendLogInner)