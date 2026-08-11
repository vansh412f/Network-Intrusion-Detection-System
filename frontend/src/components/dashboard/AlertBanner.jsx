import { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence }           from 'framer-motion'
import { AlertTriangle, AlertOctagon, Info, X } from 'lucide-react'
import { Badge } from '../ui/Badge'

const SEVERITY_CONFIG = {
  CRITICAL: {
    bg:        'rgba(220, 38, 38, 0.15)',
    border:    'rgba(220, 38, 38, 0.4)',
    text:      '#fca5a5',
    icon:      AlertOctagon,
    iconColor: '#ef4444',
    isCrit:    true
  },
  HIGH: {
    bg:        'rgba(239, 68, 68, 0.10)',
    border:    'rgba(239, 68, 68, 0.3)',
    text:      '#fca5a5',
    icon:      AlertTriangle,
    iconColor: '#ef4444',
    isCrit:    false
  },
  MEDIUM: {
    bg:        'rgba(251, 146, 60, 0.10)',
    border:    'rgba(251, 146, 60, 0.25)',
    text:      '#fdba74',
    icon:      AlertTriangle,
    iconColor: '#fb923c',
    isCrit:    false
  },
  LOW: {
    bg:        'rgba(100, 116, 139, 0.10)',
    border:    'rgba(100, 116, 139, 0.2)',
    text:      '#cbd5e1',
    icon:      Info,
    iconColor: '#64748b',
    isCrit:    false
  }
}

const BADGE_VARIANT = {
  LOW:      'low',
  MEDIUM:   'medium',
  HIGH:     'high',
  CRITICAL: 'critical'
}

function formatTime(iso) {
  if (!iso) return ''
  return new Date(iso).toLocaleTimeString()
}

export function AlertBanner({ latestAlert }) {
  const [visible,       setVisible]       = useState(false)
  const [currentAlert,  setCurrentAlert]  = useState(null)

  const dismiss = useCallback(() => setVisible(false), [])

  useEffect(() => {
    if (!latestAlert) return
    setCurrentAlert(latestAlert)
    setVisible(true)
    const timer = setTimeout(dismiss, 5000)
    return () => clearTimeout(timer)
  }, [latestAlert, dismiss])

  const severity = currentAlert?.severity || 'LOW'
  const config   = SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.LOW
  const Icon     = config.icon

  // CRITICAL-specific animated variants — breathing box shadow
  const criticalMotion = config.isCrit
    ? {
        boxShadow: [
          `0 0 0px rgba(220,38,38,0)`,
          `0 0 22px rgba(220,38,38,0.35)`,
          `0 0 0px rgba(220,38,38,0)`
        ]
      }
    : {}

  const criticalTransition = config.isCrit
    ? { boxShadow: { repeat: Infinity, duration: 2, ease: 'easeInOut' } }
    : {}

  return (
    <AnimatePresence>
      {visible && currentAlert && (
        <motion.div
          role="alert"
          aria-live="assertive"
          aria-atomic="true"
          initial={{ opacity: 0, y: -10, height: 0 }}
          animate={{
            opacity: 1,
            y:       0,
            height:  'auto',
            ...criticalMotion
          }}
          exit={{ opacity: 0, y: -10, height: 0 }}
          transition={{
            opacity:  { duration: 0.2 },
            y:        { type: 'spring', stiffness: 400, damping: 30 },
            height:   { duration: 0.2 },
            ...criticalTransition
          }}
          className="border-b overflow-hidden"
          style={{
            backgroundColor: config.bg,
            borderColor:     config.border
          }}
        >
          <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-2.5">

            <div className="flex items-center gap-3 min-w-0">
              {/* Icon — pulse on CRITICAL */}
              <motion.div
                animate={config.isCrit ? { scale: [1, 1.15, 1] } : {}}
                transition={config.isCrit ? { repeat: Infinity, duration: 1.5 } : {}}
                style={{ flexShrink: 0 }}
              >
                <Icon
                  size={18}
                  strokeWidth={2}
                  style={{ color: config.iconColor }}
                  aria-hidden="true"
                />
              </motion.div>

              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <span
                    className="text-sm font-bold"
                    style={{ color: config.text }}
                  >
                    THREAT DETECTED
                  </span>
                  <Badge variant={BADGE_VARIANT[severity]} size="xs">
                    {severity}
                  </Badge>
                  <Badge
                    variant={currentAlert.threat_type === 'MANUAL' ? 'manual' : 'ddos'}
                    size="xs"
                  >
                    {currentAlert.threat_type || 'DDoS'}
                  </Badge>
                </div>

                <p
                  className="mt-0.5 font-mono truncate"
                  style={{ fontSize: '11px', color: config.text, opacity: 0.8 }}
                >
                  {currentAlert.source_ip}
                  <span className="mx-2 opacity-40">·</span>
                  {Math.round(currentAlert.probability * 10) / 10}% confidence
                  <span className="mx-2 opacity-40">·</span>
                  {formatTime(currentAlert.createdAt)}
                  {currentAlert.geo?.country && (
                    <>
                      <span className="mx-2 opacity-40">·</span>
                      {currentAlert.geo.flag} {currentAlert.geo.country}
                    </>
                  )}
                </p>
              </div>
            </div>

            {/* Dismiss */}
            <button
              onClick={dismiss}
              className="flex-shrink-0 rounded-lg p-1 transition-opacity duration-150"
              style={{ color: config.text, opacity: 0.6 }}
              onMouseEnter={e => e.currentTarget.style.opacity = '1'}
              onMouseLeave={e => e.currentTarget.style.opacity = '0.6'}
              aria-label="Dismiss alert"
            >
              <X size={15} strokeWidth={2} />
            </button>

          </div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}