import { useState, useEffect, useMemo, useRef, useCallback } from 'react'
import { io } from 'socket.io-client'
import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'
const MAX_ALERTS = 500
const MAX_LIVE_STATS = 20
const INITIAL_GEO_LOOKUPS = 10

const api = axios.create({
  baseURL: API_URL,
  withCredentials: true
})

import { enrichWithGeo } from '../lib/geoUtils'

function mergeAlerts(currentAlerts, incomingAlerts) {
  const merged = new Map()

  incomingAlerts.forEach((alert) => {
    if (alert?._id) merged.set(alert._id, alert)
  })

  currentAlerts.forEach((alert) => {
    if (alert?._id) {
      const existing = merged.get(alert._id)
      merged.set(
        alert._id,
        existing
          ? { ...existing, ...alert, geo: alert.geo || existing.geo }
          : alert
      )
    }
  })

  return Array.from(merged.values()).sort((a, b) => {
    const timeA = new Date(a.createdAt || 0).getTime() || 0
    const timeB = new Date(b.createdAt || 0).getTime() || 0
    return timeB - timeA
  })
}

export function useSocket({ onError } = {}) {
  const [isConnected,   setIsConnected]   = useState(false)
  const [alerts,        setAlerts]        = useState([])
  const [latestAlert,   setLatestAlert]   = useState(null)
  const [liveStats,     setLiveStats]     = useState(() => {
    try {
      const stored = sessionStorage.getItem('nids_live_stats')
      return stored ? JSON.parse(stored) : []
    } catch {
      return []
    }
  })
  const [sensorMode,    setSensorMode]    = useState('idle')
  const [latestPackets, setLatestPackets] = useState(0)
  const [blocklist,     setBlocklist]     = useState([])

  const socketRef  = useRef(null)
  const seenIdsRef = useRef(new Set())
  const onErrorRef = useRef(onError)

  useEffect(() => {
    onErrorRef.current = onError
  }, [onError])

  useEffect(() => {
    sessionStorage.setItem('nids_live_stats', JSON.stringify(liveStats))
  }, [liveStats])

  const stats = useMemo(() => {
    if (!alerts.length) return { total: 0, uniqueIPs: 0, highestConf: 0 }
    const uniqueIPs   = new Set(alerts.map(a => a.source_ip)).size
    // Highest confidence across the last 20 alerts only (mirrors ThreatChart)
    const last20 = alerts.slice(0, 20)
    const highestConf = Math.max(...last20.map(a => a.probability || 0))
    return {
      total:       alerts.length,
      uniqueIPs,
      highestConf: Math.round(highestConf * 10) / 10
    }
  }, [alerts])

  const enrichAlert = useCallback(async (alertId, ip) => {
    const geo = await enrichWithGeo(ip)
    if (!geo) return
    setAlerts((currentAlerts) =>
      currentAlerts.map((alert) =>
        alert._id === alertId ? { ...alert, geo } : alert
      )
    )
  }, [])

  const addAlert = useCallback((incomingAlert) => {
    if (!incomingAlert?._id) return false
    if (seenIdsRef.current.has(incomingAlert._id)) return false
    seenIdsRef.current.add(incomingAlert._id)
    setAlerts((currentAlerts) =>
      mergeAlerts(currentAlerts, [incomingAlert]).slice(0, MAX_ALERTS)
    )
    return true
  }, [])

  useEffect(() => {
    let isMounted = true

    const loadInitialData = async () => {
      try {
        const [alertsResponse, blocklistResponse] = await Promise.all([
          api.get('/api/alerts'),
          api.get('/api/blocklist')
        ])

        if (!isMounted) return

        if (alertsResponse.data.success) {
          const fetchedAlerts = alertsResponse.data.data || []
          fetchedAlerts.forEach((alert) => {
            if (alert?._id) seenIdsRef.current.add(alert._id)
          })
          setAlerts((currentAlerts) =>
            mergeAlerts(currentAlerts, fetchedAlerts).slice(0, MAX_ALERTS)
          )
          fetchedAlerts.slice(0, INITIAL_GEO_LOOKUPS).forEach((alert) => {
            if (alert?._id) enrichAlert(alert._id, alert.source_ip)
          })
        }

        if (blocklistResponse.data.success) {
          setBlocklist(blocklistResponse.data.data || [])
        }
      } catch {
        // Initial data load failed silently — socket will still connect
        // and stream live data. Not a critical failure.
      }
    }

    socketRef.current = io(API_URL, {
      withCredentials:      true,
      transports:           ['websocket', 'polling'],
      reconnection:         true,
      reconnectionDelay:    1000,
      reconnectionAttempts: 10
    })

    const socket = socketRef.current

    socket.on('connect',    () => setIsConnected(true))
    socket.on('disconnect', () => setIsConnected(false))

    socket.on('connect_error', (error) => {
      setIsConnected(false)
      if (onErrorRef.current) onErrorRef.current(error)
    })

    socket.on('ThreatDetected', (incomingAlert) => {
      const wasAdded = addAlert(incomingAlert)
      if (!wasAdded) return
      setLatestAlert(incomingAlert)
      enrichAlert(incomingAlert._id, incomingAlert.source_ip)
    })

    socket.on('LiveStats', (data) => {
      if (data?.mode) setSensorMode(data.mode)
      setLatestPackets(data?.total_packets || 0)
      setLiveStats((currentStats) => {
        const now = new Date()
        const ms  = String(now.getMilliseconds()).padStart(3, '0')
        return [
          ...currentStats,
          {
            id:      now.getTime(),
            time:    `${now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}.${ms.slice(0, 1)}`,
            packets: data?.total_packets || 0,
            flows:   data?.total_flows   || 0
          }
        ].slice(-MAX_LIVE_STATS)
      })
    })

    socket.on('IPBlocked', (data) => {
      if (!data?.ip) return
      setBlocklist((cur) => {
        if (cur.some(e => e.ip === data.ip)) return cur
        return [data, ...cur]
      })
      setAlerts((cur) =>
        cur.map(a => a.source_ip === data.ip ? { ...a, blocked: true } : a)
      )
    })

    socket.on('IPUnblocked', (data) => {
      if (!data?.ip) return
      setBlocklist((cur) => cur.filter(e => e.ip !== data.ip))
      setAlerts((cur) =>
        cur.map(a => a.source_ip === data.ip ? { ...a, blocked: false } : a)
      )
    })

    loadInitialData()

    return () => {
      isMounted = false
      if (socketRef.current) {
        socketRef.current.disconnect()
        socketRef.current = null
      }
    }
  }, [addAlert, enrichAlert])

  return {
    isConnected,
    alerts,
    stats,
    latestAlert,
    liveStats,
    sensorMode,
    latestPackets,
    blocklist,
    setBlocklist
  }
}