import { memo } from 'react'
import { motion } from 'framer-motion'
import {
  ShieldAlert,
  Globe,
  Ban,
  TrendingUp,
  Activity
} from 'lucide-react'
import { StatCard } from '../ui/StatCard'

const SENSOR_MODE_CONFIG = {
  idle: {
    label:  'Idle',
    accent: 'slate',
    dot:    '#64748b'
  },
  simulate: {
    label:  'Simulate',
    accent: 'amber',
    dot:    '#f59e0b'
  },
  real: {
    label:  'Live',
    accent: 'green',
    dot:    '#10b981'
  }
}

const containerVariants = {
  hidden: {},
  show: {
    transition: { staggerChildren: 0.07 }
  }
}

const cardVariants = {
  hidden: { opacity: 0, y: 12 },
  show:   { opacity: 1, y: 0, transition: { duration: 0.4, ease: [0.16, 1, 0.3, 1] } }
}

function formatPackets(pkt) {
  if (!pkt) return null
  if (pkt >= 1000000) return `(${(pkt / 1000000).toFixed(1)}M pkt/win)`
  if (pkt >= 1000) return `(${(pkt / 1000).toFixed(1)}K pkt/win)`
  return `(${pkt} pkt/win)`
}

function StatsCardsInner({ stats, sensorMode, blockedCount, latestPackets }) {
  const mode = SENSOR_MODE_CONFIG[sensorMode] || SENSOR_MODE_CONFIG.idle

  const highestConfSubtext =
    stats.highestConf >= 99 ? '(Critical)' :
    stats.highestConf >= 95 ? '(High)'     :
    stats.highestConf >= 85 ? '(Medium)'   : null

  return (
    <motion.div
      className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5"
      variants={containerVariants}
      initial="hidden"
      animate="show"
    >
      <motion.div variants={cardVariants}>
        <StatCard
          icon={ShieldAlert}
          label="Session Alerts"
          value={stats.total || 0}
          accent="red"
        />
      </motion.div>

      <motion.div variants={cardVariants}>
        <StatCard
          icon={Globe}
          label="Unique IPs"
          value={stats.uniqueIPs || 0}
          accent="blue"
        />
      </motion.div>

      <motion.div variants={cardVariants}>
        <StatCard
          icon={Ban}
          label="Blocked IPs"
          value={blockedCount || 0}
          accent="amber"
        />
      </motion.div>

      <motion.div variants={cardVariants}>
        <StatCard
          icon={TrendingUp}
          label="Highest Conf"
          value={stats.highestConf || 0}
          unit="%"
          accent="red"
          subtext={highestConfSubtext}
        />
      </motion.div>

      <motion.div variants={cardVariants}>
        <StatCard
          icon={Activity}
          label="Sensor Mode"
          value={mode.label}
          accent={mode.accent}
          subtext={formatPackets(latestPackets)}
        />
      </motion.div>
    </motion.div>
  )
}

export const StatsCards = memo(StatsCardsInner)