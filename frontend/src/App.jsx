import { useState, useEffect } from 'react'
import axios from 'axios'

// Custom hook for Socket.io + REST data
import { useSocket } from './hooks/useSocket'

// UI Components
import { Header } from './components/Header'
import { AlertBanner } from './components/AlertBanner'
import { TrafficGraph } from './components/TrafficGraph'
import { ThreatChart } from './components/ThreatChart'
import { SensorLog } from './components/SensorLog'
import { BackendLog } from './components/BackendLog'
import { ThreatTable } from './components/ThreatTable'
import { ManualInputModal } from './components/ManualInputModal'
import { DemoVideoModal } from './components/DemoVideoModal'

// Use VITE_API_URL (baked in at Docker build time) or fallback for local dev
const BACKEND_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000'


function App() {
  // ══════════════════════════════════════════════════════════════════════════
  // STATE & DATA
  // ══════════════════════════════════════════════════════════════════════════

  // Real-time data from backend via Socket.io
  const {
    isConnected,    // Boolean: Socket.io connection status
    alerts,         // Array: Recent threat alerts (max 50)
    stats,          // Object: { total, uniqueIPs, highestConf }
    latestAlert,    // Object: Most recent alert (for banner)
    liveStats,      // Array: Traffic data for graph (last 20 windows)
    sensorMode,     // String: "real" | "simulate" | null
    latestPackets,  // Number: Packets in most recent window
  } = useSocket()

  // Local UI state
  const [showManualInput, setShowManualInput] = useState(false)
  const [showDemoVideo, setShowDemoVideo] = useState(false)

  // ── Wake up Render Sensor on page load ────────────────────────────────────
  // Render free tier spins down services after 15 mins of inactivity.
  // Pinging the sensor URL on mount ensures it wakes up when someone visits
  // the dashboard, so simulated traffic starts flowing quickly.
  useEffect(() => {
    const sensorUrl = import.meta.env.VITE_SENSOR_URL
    if (sensorUrl) {
      console.log('[App] Waking up Render sensor at:', sensorUrl)
      fetch(sensorUrl, { mode: 'no-cors' }).catch(() => {
        // Silently ignore — we just want to trigger the wake-up, not read the response
      })
    }
  }, [])


  // ══════════════════════════════════════════════════════════════════════════
  // EVENT HANDLERS
  // ══════════════════════════════════════════════════════════════════════════

  /**
   * Sends manual features to backend for real ML prediction.
   * Called by ManualInputModal when user clicks "Run Prediction".
   *
   * @param {Object} features - 15 network flow features
   */
  const handleManualPredict = async (features) => {
    try {
      console.log('[Manual] Submitting features for prediction:', features)
      const response = await axios.post(`${BACKEND_URL}/api/predict/manual`, { features })

      console.log('[Manual] Prediction result:', response.data)

      const { probability, label, saved } = response.data

      // Show result to user
      alert(
        `🔍 ML Prediction Result\n\n` +
        `Label: ${label}\n` +
        `Confidence: ${probability}%\n` +
        `${saved ? '✅ Saved to database' : ''}\n\n` +
        `${label === 'MALICIOUS' ? '🚨 Threat detected!' : '✅ Traffic appears normal'}`
      )
    } catch (error) {
      console.error('[Manual] Prediction failed:', error.message)
      throw error // Re-throw so modal can handle loading state
    }
  }


  // ══════════════════════════════════════════════════════════════════════════
  // RENDER
  // ══════════════════════════════════════════════════════════════════════════

  return (
    <div className="min-h-screen bg-slate-900 text-white">

      {/* ── Header ─────────────────────────────────────────────────────────── */}
      <Header
        isConnected={isConnected}
        onOpenManualInput={() => setShowManualInput(true)}
        onOpenDemo={() => setShowDemoVideo(true)}
      />

      {/* ── Alert Banner (appears below header when threat detected) ──────── */}
      <AlertBanner latestAlert={latestAlert} />

      {/* ── Main Content ───────────────────────────────────────────────────── */}
      <main className="max-w-7xl mx-auto px-3 sm:px-6 py-4 sm:py-6 space-y-4 sm:space-y-6">

        {/* Row 1: Graphs */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
          <TrafficGraph
            liveStats={liveStats}
            latestPackets={latestPackets}
          />
          <ThreatChart alerts={alerts} />
        </div>

        {/* Row 2: Log Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
          <SensorLog
            sensorMode={sensorMode || 'simulate'}
            liveStats={liveStats}
            alerts={alerts}
          />
          <BackendLog
            isConnected={isConnected}
            alerts={alerts}
            sensorMode={sensorMode || 'simulate'}
          />
        </div>

        {/* Row 3: Threat Table */}
        <ThreatTable
          alerts={alerts}
          stats={stats}
        />

      </main>

      {/* ── Informational Footer ───────────────────────────────────────────── */}
      <Footer />

      {/* ── Manual Input Modal ─────────────────────────────────────────────── */}
      <ManualInputModal
        isOpen={showManualInput}
        onClose={() => setShowManualInput(false)}
        onSubmit={handleManualPredict}
      />

      {/* ── Demo Video Modal ───────────────────────────────────────────────── */}
      <DemoVideoModal
        isOpen={showDemoVideo}
        onClose={() => setShowDemoVideo(false)}
      />

    </div>
  )
}


// ══════════════════════════════════════════════════════════════════════════════
// FOOTER COMPONENT (Separated for cleaner App component)
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Informational footer with:
 *  - About NIDS
 *  - Operating modes explanation
 *  - Dashboard components guide
 *  - Tech stack badges
 */
function Footer() {
  return (
    <footer className="border-t border-slate-700 mt-8 bg-slate-800/50">
      <div className="max-w-7xl mx-auto px-6 py-6">

        {/* Bottom Bar: Tech Stack + Links */}
        <div className="flex flex-wrap items-center justify-between gap-4 text-xs text-slate-500">
          
          {/* Left: Tech Stack */}
          <div className="flex items-center gap-4">
            <span>🧠 XGBoost</span>
            <span>📈 99.85% Accuracy</span>
            <span>📦 15 Features</span>
            <span>🗄️ MongoDB</span>
            <span>⚡ Socket.io</span>
          </div>

          {/* Right: Links */}
          <div className="flex items-center gap-4">
            <a
              href="https://github.com/vansh412f"
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-white transition-colors"
            >
              GitHub
            </a>
            <span>CIC-DDoS2019</span>
          </div>

        </div>

      </div>
    </footer>
  )
}


export default App