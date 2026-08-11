import { useState, useEffect, useCallback } from 'react'
import { motion } from 'framer-motion'
import axios from 'axios'

import { useSocket } from '../hooks/useSocket'
import { useAuth }   from '../hooks/useAuth'

import { Header }         from '../components/layout/Header'
import { Footer }         from '../components/layout/Footer'
import { AlertBanner }    from '../components/dashboard/AlertBanner'
import { StatsCards }     from '../components/dashboard/StatsCards'
import { TrafficGraph }   from '../components/dashboard/TrafficGraph'
import { ThreatChart }    from '../components/dashboard/ThreatChart'
import { ThreatTable }    from '../components/dashboard/ThreatTable/ThreatTable'
import { BlocklistPanel } from '../components/dashboard/BlocklistPanel/BlocklistPanel'
import { SensorLog }      from '../components/logs/SensorLog'
import { BackendLog }     from '../components/logs/BackendLog'
import { ManualInputModal } from '../components/modals/ManualInputModal'
import { DemoVideoModal }   from '../components/modals/DemoVideoModal'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'

const api = axios.create({
  baseURL:         API_URL,
  withCredentials: true
})

const rowVariants = {
  hidden: { opacity: 0, y: 16 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.45, ease: [0.16, 1, 0.3, 1] } }
}

export default function DashboardPage({ addToast, sensorUrl }) {
  const { isAuthenticated } = useAuth()

  const {
    isConnected,
    alerts,
    stats,
    latestAlert,
    liveStats,
    sensorMode,
    latestPackets,
    blocklist,
    setBlocklist
  } = useSocket({
    onError: () => addToast('WebSocket connection failed', 'error')
  })
  const [showWakeUp, setShowWakeUp] = useState(false)
  const [showManualInput, setShowManualInput] = useState(false)
  const [showDemoVideo,   setShowDemoVideo]   = useState(false)

  useEffect(() => {
    if (sensorUrl) fetch(sensorUrl, { mode: 'no-cors' }).catch(() => {})
  }, [sensorUrl])
  // Show wake-up banner if not connected after 3 seconds
useEffect(() => {
  if (isConnected) {
    setShowWakeUp(false)
    return
  }
  const timer = setTimeout(() => {
    if (!isConnected) setShowWakeUp(true)
  }, 3000)
  return () => clearTimeout(timer)
}, [isConnected])
  const handleManualPredict = useCallback(async (features) => {
    if (!isAuthenticated) {
      addToast('Please log in to run predictions', 'warning')
      return
    }
    try {
      const response = await api.post('/api/predict/manual', { features })
      const { probability, label, saved } = response.data
      
      // Determine severity string matching backend logic
      const pct = Math.round(probability * 10) / 10
      const severity = pct >= 99 ? 'CRITICAL' :
                       pct >= 95 ? 'HIGH' :
                       pct >= 85 ? 'MEDIUM' : 'LOW'

      if (label === 'MALICIOUS') {
        addToast(`${probability}% confidence${saved ? ' — saved to DB' : ''}`, 'error', 6000, severity)
      } else {
        addToast(`${probability}% confidence`, 'success', 4000, 'NORMAL TRAFFIC')
      }
      return response.data
    } catch (error) {
      const message = error.response?.data?.message || 'Prediction failed'
      // If rate limited, the backend sends 'Prediction limit reached (10 per 15 minutes).'
      addToast(message, error.response?.status === 429 ? 'warning' : 'error')
      throw error
    }
  }, [isAuthenticated, addToast])

  const handleBlockIP = useCallback(async (ip, reason) => {
    if (!isAuthenticated) {
      addToast('Please log in to block IPs', 'warning')
      return
    }
    try {
      await api.post('/api/blocklist/block', { ip, reason })
      addToast(`${ip} has been blocked`, 'blocked')
    } catch (error) {
      if (error.response?.status === 429) {
        addToast('Demo limit reached — max 3 blocks per 30 minutes per user', 'warning', 6000)
        return
      }
      const message = error.response?.data?.message || 'Failed to block IP'
      addToast(message, 'error')
    }
  }, [isAuthenticated, addToast])

  const handleUnblockIP = useCallback(async (ip) => {
    if (!isAuthenticated) {
      addToast('Please log in to unblock IPs', 'warning')
      return
    }
    try {
      await api.post('/api/blocklist/unblock', { ip })
      addToast(`${ip} has been unblocked`, 'success')
    } catch (error) {
      const message = error.response?.data?.message || 'Failed to unblock IP'
      addToast(message, 'error')
    }
  }, [isAuthenticated, addToast])

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--color-bg-page)' }}>

      <Header
        isConnected={isConnected}
        onOpenManualInput={() => setShowManualInput(true)}
        onOpenDemo={() => setShowDemoVideo(true)}
      />

      <AlertBanner latestAlert={latestAlert} />
      {showWakeUp && !isConnected && (
  <motion.div
    initial={{ opacity: 0, height: 0 }}
    animate={{ opacity: 1, height: 'auto' }}
    exit={{ opacity: 0, height: 0 }}
    className="border-b"
    style={{
      backgroundColor: 'rgba(59,130,246,0.08)',
      borderColor:     'rgba(59,130,246,0.2)'
    }}
  >
    <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-2.5">
      <span className="h-4 w-4 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin flex-shrink-0" />
      <p style={{ fontSize: '13px', color: 'var(--color-text-secondary)' }}>
        Connecting to backend — Render services take ~60s on first load...
      </p>
    </div>
  </motion.div>
)}
      <main className="mx-auto max-w-7xl px-3 py-4 sm:px-6 sm:py-5 space-y-4">

        <StatsCards
          stats={stats}
          sensorMode={sensorMode}
          blockedCount={blocklist.length}
          latestPackets={latestPackets}
        />

        {/* ROW 1: TrafficGraph + SensorLog */}
        <motion.div
          className="grid grid-cols-1 lg:grid-cols-[55fr_45fr] gap-4 items-stretch"
          variants={rowVariants}
          initial="hidden"
          animate="show"
        >
          <div className="h-full">
            <TrafficGraph liveStats={liveStats} latestPackets={latestPackets} />
          </div>
          <div className="h-full">
            <SensorLog sensorMode={sensorMode || 'idle'} liveStats={liveStats} alerts={alerts} />
          </div>
        </motion.div>

        {/* ROW 2: ThreatChart + BackendLog */}
        <motion.div
          className="grid grid-cols-1 lg:grid-cols-[55fr_45fr] gap-4 items-stretch"
          variants={rowVariants}
          initial="hidden"
          animate="show"
        >
          <div className="h-full">
            <ThreatChart alerts={alerts} />
          </div>
          <div className="h-full">
            <BackendLog isConnected={isConnected} alerts={alerts} sensorMode={sensorMode || 'idle'} />
          </div>
        </motion.div>

        {/* ROW 3: ThreatTable + BlocklistPanel */}
        <motion.div
          className="grid grid-cols-1 lg:grid-cols-2 gap-4 items-stretch"
          variants={rowVariants}
          initial="hidden"
          animate="show"
        >
          <div className="h-full">
            <ThreatTable alerts={alerts} onBlockIP={handleBlockIP} isAuthenticated={isAuthenticated} />
          </div>
          <div className="h-full">
            <BlocklistPanel blocklist={blocklist} onUnblockIP={handleUnblockIP} isAuthenticated={isAuthenticated} />
          </div>
        </motion.div>

      </main>

      <Footer />

      <ManualInputModal
        isOpen={showManualInput}
        onClose={() => setShowManualInput(false)}
        onSubmit={handleManualPredict}
      />
      <DemoVideoModal
        isOpen={showDemoVideo}
        onClose={() => setShowDemoVideo(false)}
      />
    </div>
  )
}