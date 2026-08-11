import { useMemo, useState } from 'react'
import { motion } from 'framer-motion'
import { useInView } from 'react-intersection-observer'
import { useSocket } from '../hooks/useSocket'
import { Header } from '../components/layout/Header'
import { Footer } from '../components/layout/Footer'
import { Card } from '../components/ui/Card'
import { WorldMap } from '../components/ui/WorldMap'
import { ConfidenceGauge } from '../components/analytics/ConfidenceGauge'
import { SeverityStackedBar } from '../components/analytics/SeverityStackedBar'
import { AnalyticsStatCard } from '../components/analytics/AnalyticsStatCard'
import { TopAttackerCard } from '../components/analytics/TopAttackerCard'
import { SessionSummaryCard } from '../components/analytics/SessionSummaryCard'
import { TopIPsTable } from '../components/analytics/TopIPsTable'
import { ChartScopeFilter } from '../components/analytics/ChartScopeFilter'
import { SeverityDonutChart } from '../components/analytics/SeverityDonutChart'
import { ThreatTypesBarChart } from '../components/analytics/ThreatTypesBarChart'
import { ThreatOriginMapSection } from '../components/analytics/ThreatOriginMapSection'
import {
  ShieldAlert, Ban, TrendingUp,
  Activity, AlertTriangle
} from 'lucide-react'

// ── Constants ────────────────────────────────────────────────────────────────

import { SEVERITY_COLORS } from '../lib/severityColors'

const SEVERITY_ORDER = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const fadeUp = {
  hidden: { opacity: 0, y: 18 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.5, ease: [0.16, 1, 0.3, 1] } }
}

const stagger = (delay = 0.08) => ({
  hidden: {},
  show:   { transition: { staggerChildren: delay } }
})

// ── Main page ─────────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  const { alerts, isConnected } = useSocket()
  const [chartWindow, setChartWindow] = useState('all')

  const [headerRef,   headerInView]   = useInView({ triggerOnce: true, threshold: 0.1 })
  const [statsRef,    statsInView]    = useInView({ triggerOnce: true, threshold: 0.1 })
  const [mapRef,      mapInView]      = useInView({ triggerOnce: true, threshold: 0.05 })
  const [chartsRef,   chartsInView]   = useInView({ triggerOnce: true, threshold: 0.1 })
  const [insightRef,  insightInView]  = useInView({ triggerOnce: true, threshold: 0.1 })
  const [ipsRef,      ipsInView]      = useInView({ triggerOnce: true, threshold: 0.1 })

  const chartAlerts = useMemo(() => {
    if (chartWindow === 'last10') return alerts.slice(0, 10)
    if (chartWindow === 'last25') return alerts.slice(0, 25)
    return alerts
  }, [alerts, chartWindow])

  const avgConfidence = useMemo(() => {
    if (!chartAlerts.length) return 0
    const sum = chartAlerts.reduce((acc, a) => acc + (a.probability || 0), 0)
    return Math.round((sum / chartAlerts.length) * 10) / 10
  }, [chartAlerts])

  const criticalCount = useMemo(
    () => chartAlerts.filter(a => a.severity === 'CRITICAL').length,
    [chartAlerts]
  )

  const blockedCount = useMemo(
    () => chartAlerts.filter(a => a.blocked).length,
    [chartAlerts]
  )

  const severityData = useMemo(() => {
    const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
    chartAlerts.forEach(a => { if (counts[a.severity] !== undefined) counts[a.severity]++ })
    return SEVERITY_ORDER.map(name => ({ name, value: counts[name] }))
  }, [chartAlerts])

  const typeData = useMemo(() => {
    const counts = {}
    chartAlerts.forEach(a => {
      const type = a.threat_type || 'DDoS'
      counts[type] = (counts[type] || 0) + 1
    })
    return Object.entries(counts).map(([name, value]) => ({ name, value }))
  }, [chartAlerts])

  const topIPs = useMemo(() => {
    const counts = {}
    chartAlerts.forEach(a => {
      if (a.source_ip && a.source_ip !== 'MANUAL-INPUT') {
        counts[a.source_ip] = (counts[a.source_ip] || 0) + 1
      }
    })
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }))
  }, [chartAlerts])

  const topAttacker = useMemo(() => {
    if (!topIPs.length) return null
    const ip    = topIPs[0].ip
    const alert = chartAlerts.find(a => a.source_ip === ip)
    return {
      ip,
      count:    topIPs[0].count,
      severity: alert?.severity || 'LOW',
      geo:      alert?.geo || null
    }
  }, [topIPs, chartAlerts])

  const uniqueIPCount = useMemo(
    () => new Set(chartAlerts.map(a => a.source_ip)).size,
    [chartAlerts]
  )

  const geoAlerts = useMemo(
    () => chartAlerts.filter(a => a.geo?.lat != null && a.geo?.lng != null),
    [chartAlerts]
  )

  return (
    <div className="min-h-screen" style={{ backgroundColor: 'var(--color-bg-page)' }}>
      <Header isConnected={isConnected} />

      <main className="mx-auto max-w-7xl px-3 py-5 sm:px-6 space-y-5">

        {/* Page header */}
        <motion.div
          ref={headerRef}
          variants={fadeUp}
          initial="hidden"
          animate={headerInView ? 'show' : 'hidden'}
        >
          <h1
            className="text-xl font-bold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            Analytics
          </h1>
          <p className="mt-1" style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}>
            Threat intelligence from{' '}
            <span style={{ color: 'var(--color-text-secondary)', fontWeight: 600 }}>
              {chartAlerts.length}
            </span>
            {' '}session alerts
            {geoAlerts.length > 0 && (
              <span style={{ color: 'var(--color-text-muted)' }}>
                {' '}·{' '}
                <span style={{ color: 'var(--color-live-green)' }}>
                  {geoAlerts.length}
                </span>
                {' '}geo-mapped
              </span>
            )}
          </p>
        </motion.div>
        {alerts.length === 0 && (
  <motion.div
    initial={{ opacity: 0, y: 12 }}
    animate={{ opacity: 1, y: 0 }}
    transition={{ duration: 0.4 }}
  >
    <Card className="p-8">
      <div className="flex flex-col items-center gap-4 text-center">
        <div
          className="flex h-14 w-14 items-center justify-center rounded-2xl"
          style={{
            backgroundColor: 'rgba(59,130,246,0.08)',
            border:          '1px solid rgba(59,130,246,0.15)'
          }}
        >
          <Activity
            size={24}
            strokeWidth={1.5}
            style={{ color: 'var(--color-primary-blue)' }}
          />
        </div>
        <div>
          <h2
            className="text-base font-semibold"
            style={{ color: 'var(--color-text-primary)' }}
          >
            No session data yet
          </h2>
          <p
            className="mt-1 max-w-sm leading-relaxed"
            style={{ fontSize: '13px', color: 'var(--color-text-muted)' }}
          >
            Analytics will populate when the sensor starts detecting threats.
            Open the dashboard and wait for the sensor to begin sending data.
          </p>
        </div>
        <a
          href="/dashboard"
          className="rounded-lg px-5 py-2 text-sm font-semibold text-white transition-colors"
          style={{ backgroundColor: 'var(--color-primary-blue)' }}
        >
          Go to Dashboard
        </a>
      </div>
    </Card>
  </motion.div>
)}
        {/* Stat cards */}
        <motion.div
          ref={statsRef}
          className="grid grid-cols-2 gap-3 sm:grid-cols-4"
          variants={stagger(0.07)}
          initial="hidden"
          animate={statsInView ? 'show' : 'hidden'}
        >
          <AnalyticsStatCard
            icon={ShieldAlert}
            label="Session Alerts"
            value={chartAlerts.length}
            accent="blue"
            note="Current session only"
          />
          <AnalyticsStatCard
            icon={TrendingUp}
            label="Avg Confidence"
            value={avgConfidence > 0 ? `${avgConfidence}%` : '—'}
            accent="amber"
            note={avgConfidence >= 90 ? 'Excellent detection' : avgConfidence >= 75 ? 'High accuracy' : chartAlerts.length === 0 ? 'No data yet' : 'Moderate'}
          />
          <AnalyticsStatCard
            icon={AlertTriangle}
            label="Critical Alerts"
            value={criticalCount}
            accent="red"
            note={chartAlerts.length > 0 ? `${((criticalCount / chartAlerts.length) * 100).toFixed(1)}% of total` : 'No data yet'}
          />
          <AnalyticsStatCard
  icon={Ban}
  label="Alerts Blocked"
  value={blockedCount}
  accent="green"
  note={blockedCount > 0 ? 'From blocked IPs' : 'None blocked yet'}
/>
        </motion.div>

        {/* World Map */}
        <motion.div
          ref={mapRef}
          initial={{ opacity: 0, y: 20 }}
          animate={mapInView ? { opacity: 1, y: 0 } : {}}
          transition={{ duration: 0.55 }}
        >
          <ThreatOriginMapSection alerts={chartAlerts} geoCount={geoAlerts.length} />
        </motion.div>

        <ChartScopeFilter chartWindow={chartWindow} onChange={setChartWindow} />

        {/* Charts row */}
        <motion.div
          ref={chartsRef}
          className="grid grid-cols-1 gap-4 lg:grid-cols-3"
          variants={stagger(0.1)}
          initial="hidden"
          animate={chartsInView ? 'show' : 'hidden'}
        >
          <motion.div variants={fadeUp}>
            <SeverityDonutChart data={severityData} hasData={chartAlerts.length > 0} />
          </motion.div>

          <motion.div variants={fadeUp}>
            <ThreatTypesBarChart data={typeData} hasData={chartAlerts.length > 0} />
          </motion.div>

          {/* Confidence gauge */}
          <motion.div variants={fadeUp}>
            <Card className="p-4 flex flex-col">
              <h2
                className="mb-3 text-sm font-semibold"
                style={{ color: 'var(--color-text-primary)' }}
              >
                Detection Quality
              </h2>
              <div className="flex flex-1 items-center justify-center">
                <ConfidenceGauge value={avgConfidence} />
              </div>
              <p
                className="mt-3 text-center"
                style={{ fontSize: '11px', color: 'var(--color-text-muted)', lineHeight: '1.5' }}
              >
                Average ML confidence score across all{' '}
                <span style={{ color: 'var(--color-text-secondary)' }}>
                  {chartAlerts.length}
                </span>
                {' '}session detections
              </p>
            </Card>
          </motion.div>
        </motion.div>

        {/* Insight cards */}
        <motion.div
          ref={insightRef}
          className="grid grid-cols-1 gap-4 sm:grid-cols-3"
          variants={stagger(0.09)}
          initial="hidden"
          animate={insightInView ? 'show' : 'hidden'}
        >
          <TopAttackerCard topAttacker={topAttacker} />

          {/* Severity ratio */}
          <motion.div variants={fadeUp}>
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-3">
                <Activity
                  size={13}
                  strokeWidth={1.75}
                  style={{ color: 'var(--color-warning-amber)' }}
                />
                <h3
                  className="text-xs font-semibold uppercase"
                  style={{ letterSpacing: '0.08em', color: 'var(--color-text-muted)' }}
                >
                  Severity Ratio
                </h3>
              </div>

              {chartAlerts.length === 0 ? (
                <div className="flex h-20 items-center justify-center">
                  <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                    No data yet
                  </p>
                </div>
              ) : (
                <div className="space-y-2.5">
                  <SeverityStackedBar data={severityData} />

                  <div className="grid grid-cols-2 gap-1.5 mt-2">
                    {severityData.map(({ name, value }) => (
                      <div
                        key={name}
                        className="rounded-lg p-1.5"
                        style={{
                          backgroundColor: `${SEVERITY_COLORS[name]}08`,
                          border:          `1px solid ${SEVERITY_COLORS[name]}20`
                        }}
                      >
                        <p style={{ fontSize: '15px', fontWeight: 800, color: SEVERITY_COLORS[name], lineHeight: 1 }}>
                          {value}
                        </p>
                        <p style={{ fontSize: '9px', color: 'var(--color-text-muted)', marginTop: '1px', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
                          {name}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </Card>
          </motion.div>

          <SessionSummaryCard
            alertCount={chartAlerts.length}
            uniqueIPCount={uniqueIPCount}
            blockedCount={blockedCount}
            geoCount={geoAlerts.length}
          />
        </motion.div>

        <TopIPsTable
          topIPs={topIPs}
          alerts={chartAlerts}
          ipsRef={ipsRef}
          ipsInView={ipsInView}
        />

      </main>

      <Footer />
    </div>
  )
}