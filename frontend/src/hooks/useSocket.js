// ============================================================
// src/hooks/useSocket.js
// Real-time data hook for:
//  - ThreatDetected (Socket.io) → updates alerts + stats
//  - LiveStats (Socket.io)      → updates live traffic chart + mode
//  - SensorLog (Socket.io)      → stores real sensor logs (if backend emits)
// Also loads initial alerts via REST (GET /api/alerts).
// ============================================================

import { useState, useEffect, useRef } from 'react'
import { io } from 'socket.io-client'
import axios from 'axios'

// Backend URL:
// - Local dev: Vite proxy handles /api REST calls, but Socket.io needs explicit URL
// - Docker production: VITE_API_URL is baked in at build time (no Vite proxy in static serve)
const BACKEND_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'

// Max alerts stored in memory to keep UI fast
const MAX_ALERTS = 50

export function useSocket() {
  // ── State ──────────────────────────────────────────────────
  const [isConnected, setIsConnected] = useState(false)
  const [alerts, setAlerts] = useState([])
  const [latestAlert, setLatestAlert] = useState(null)

  const [liveStats, setLiveStats] = useState([])
  const [sensorMode, setSensorMode] = useState(null)
  const [latestPackets, setLatestPackets] = useState(0)

  // Used for real mode only (if backend emits SensorLog)
  const [realLogs, setRealLogs] = useState([])

  const [stats, setStats] = useState({
    total: 0,
    uniqueIPs: 0,
    highestConf: 0
  })

  // Keep socket instance across renders
  const socketRef = useRef(null)

  // ── Helper: compute dashboard stats from alerts list ───────
  const calculateStats = (alertsList) => {
    if (!alertsList.length) return { total: 0, uniqueIPs: 0, highestConf: 0 }

    const uniqueIPs = new Set(alertsList.map(a => a.source_ip)).size
    const highestConf = Math.max(...alertsList.map(a => a.probability))

    return {
      total: alertsList.length,
      uniqueIPs,
      highestConf: Math.round(highestConf * 10) / 10
    }
  }


  // ── Main effect: runs once on mount ─────────────────────────
  useEffect(() => {
    // 1) Load initial alerts from MongoDB
    // Inlined as async IIFE to avoid lint issues with calling setState
    // from a function defined outside this effect
    ;(async () => {
      try {
        // Use absolute URL so this works in Docker (no Vite proxy in static serve)
        const response = await axios.get(`${BACKEND_URL}/api/alerts`)
        if (response.data.success) {
          const existing = response.data.data
          setAlerts(existing)
          setStats({
            total: existing.length,
            uniqueIPs: new Set(existing.map(a => a.source_ip)).size,
            highestConf: existing.length
              ? Math.round(Math.max(...existing.map(a => a.probability)) * 10) / 10
              : 0
          })
          console.log(`[useSocket] Loaded ${existing.length} existing alerts`)
        }
      } catch (error) {
        console.error('[useSocket] Failed to load existing alerts:', error.message)
      }
    })()

    // 2) Create Socket.io connection
    console.log('[useSocket] Connecting to:', BACKEND_URL)

    socketRef.current = io(BACKEND_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 10
    })

    const socket = socketRef.current

    // 3) Connection established
    socket.on('connect', () => {
      console.log('[useSocket] ✅ Connected | ID:', socket.id)
      setIsConnected(true)
    })

    // 4) Connection lost
    socket.on('disconnect', (reason) => {
      console.log('[useSocket] ❌ Disconnected | Reason:', reason)
      setIsConnected(false)
    })

    // 5) Threat alerts pushed by backend
    socket.on('ThreatDetected', (newAlert) => {
      console.log('[useSocket] 🚨 ThreatDetected:', newAlert.source_ip)

      setLatestAlert(newAlert)
      setAlerts(prev => {
        const updated = [newAlert, ...prev].slice(0, MAX_ALERTS)
        setStats(calculateStats(updated))
        return updated
      })
    })

    // 6) Live traffic updates pushed by backend
    socket.on('LiveStats', (data) => {
      console.log('[useSocket] LiveStats:', data.total_packets, 'packets')

      if (data.mode) setSensorMode(data.mode)
      setLatestPackets(data.total_packets)

      // Keep last ~40s (20 windows of 2 seconds)
      setLiveStats(prev => {
        const updated = [
          ...prev,
          {
            time: new Date().toLocaleTimeString(),
            packets: data.total_packets,
            flows: data.total_flows
          }
        ].slice(-20)
        return updated
      })
    })

    // 7) Real sensor logs (only if backend emits SensorLog events)
    socket.on('SensorLog', (logData) => {
      console.log('[useSocket] SensorLog:', logData?.message)

      setRealLogs(prev => {
        const entry = {
          id: Date.now(),
          time: new Date().toLocaleTimeString(),
          type: logData.type || 'info',
          message: logData.message
        }
        return [...prev, entry].slice(-100)
      })
    })

    // 8) Connection error
    socket.on('connect_error', (error) => {
      console.error('[useSocket] Connection error:', error.message)
      setIsConnected(false)
    })

    // 9) Cleanup on unmount
    return () => {
      console.log('[useSocket] Cleaning up socket connection')
      socket.disconnect()
    }
  }, [])

  // ── Return hook state ───────────────────────────────────────
  return {
    isConnected,
    alerts,
    stats,
    latestAlert,
    liveStats,
    sensorMode,
    latestPackets,
    realLogs
  }
}