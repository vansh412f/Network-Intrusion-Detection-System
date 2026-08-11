import { useState, useEffect, useRef, memo } from 'react'
import { Terminal } from 'lucide-react'
import { LogPanel } from './LogPanel'

const BENIGN_IPS = [
  '142.250.80.46', '13.69.116.109', '140.82.114.21',
  '151.101.1.140', '104.21.45.231', '52.84.163.89',
  '192.168.31.1',  '8.8.8.8'
]

const MAX_LOGS = 200

function SensorLogInner({ sensorMode, liveStats, alerts }) {
  const [logs, setLogs]              = useState([])
  const [threatCount, setThreatCount] = useState(0)
  const processedWindowRef           = useRef(new Set())
  const processedAlertRef            = useRef(new Set())
  const totalFlowsRef                = useRef(0)

  useEffect(() => {
    if (!liveStats || liveStats.length === 0) return

    const latest    = liveStats[liveStats.length - 1]
    const windowKey = `${latest.time}-${latest.packets}`

    if (processedWindowRef.current.has(windowKey)) return
    processedWindowRef.current.add(windowKey)

    if (processedWindowRef.current.size > MAX_LOGS) {
      const first = processedWindowRef.current.values().next().value
      processedWindowRef.current.delete(first)
    }

    totalFlowsRef.current += (latest.flows || 2)

    const windowLog = {
      id:      `w-${latest.time}-${Date.now()}`,
      type:    'window',
      message: `[${latest.time}] > Window #${String(liveStats.length).padStart(4, '0')} | Flows: ${latest.flows || 2} | Packets: ${latest.packets.toLocaleString()}`
    }

    const flowLogs = Array.from({ length: Math.min(latest.flows || 2, 4) }, (_, i) => {
      const conf  = (Math.random() * 25 + 5).toFixed(1)
      const label = sensorMode === 'real'
        ? `flow #${i + 1}`
        : BENIGN_IPS[Math.floor(Math.random() * BENIGN_IPS.length)]
      return {
        id:      `f-${latest.time}-${i}-${Date.now()}`,
        type:    'benign',
        message: `[${latest.time}]   + BENIGN  ${label}  conf: ${conf}%`
      }
    })

    setLogs(prev => [...prev, windowLog, ...flowLogs].slice(-MAX_LOGS))
  }, [liveStats, sensorMode])

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

    setThreatCount(prev => prev + 1)
    const time = new Date().toLocaleTimeString()

    setLogs(prev => [...prev, {
      id:      `a-${alertKey}-${Date.now()}`,
      type:    'malicious',
      message: `[${time}]   ! MALICIOUS  ${latest.source_ip}  conf: ${latest.probability}%`
    }].slice(-MAX_LOGS))
  }, [alerts])

  const isReal     = sensorMode === 'real'
  const badgeColor = isReal ? '#10b981' : '#f59e0b'
  const badgeText  = isReal ? 'REAL' : 'SIMULATE'

  const metrics = [
    { label: 'WINDOWS', value: liveStats.length > 0 ? liveStats.length.toLocaleString() : '0' },
    { label: 'THREATS', value: threatCount.toLocaleString() },
    { label: 'MODE',    value: sensorMode?.toUpperCase() || 'IDLE' }
  ]

  return (
    <LogPanel
      title="Sensor Log"
      subtitle={`sensor.py — ${isReal ? 'live capture' : 'simulated'}`}
      logs={logs}
      icon={Terminal}
      badgeText={badgeText}
      badgeColor={badgeColor}
      badgeTextColor={badgeColor}
      metrics={metrics}
    />
  )
}

export const SensorLog = memo(SensorLogInner)