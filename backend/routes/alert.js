const express  = require('express')
const router   = express.Router()
const path     = require('path')
const { spawn } = require('child_process')

const Alert       = require('../models/Alert')
const User        = require('../models/User')
const logger      = require('../logger')
const requireAuth = require('../middleware/requireAuth')
const validateSecret          = require('../middleware/validateSecret')
const { manualPredictLimiter } = require('../middleware/rateLimiter')
const { internalAlertSchema, manualPredictSchema, statsSchema } = require('../schemas/alertSchemas')
const { sendThreatAlert } = require('../services/emailService')

const MAX_STORED_ALERTS = 500

function computeSeverity(probability) {
  const pct = Math.round(probability * 10) / 10
  if (pct >= 99) return 'CRITICAL'
  if (pct >= 95) return 'HIGH'
  if (pct >= 85) return 'MEDIUM'
  return 'LOW'
}

async function trimAlerts() {
  const cutoff = await Alert
    .findOne()
    .sort({ createdAt: -1, _id: -1 })
    .skip(MAX_STORED_ALERTS)
    .select('_id')
    .lean()
  if (!cutoff) return
  const { deletedCount } = await Alert.deleteMany({ _id: { $lte: cutoff._id } })
  if (deletedCount > 0) logger.info(`🗑️  [Cleanup] Removed ${deletedCount} old alert(s)`)
}

async function sendEmailAlerts(alert) {
  try {
    const recipients = await User.find({
      email_notifications:    true,
      verified:               true,           // Never email unverified accounts
      min_severity_for_email: { $ne: 'NONE' }
    })

    if (recipients.length === 0) return

    const severityOrder = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    const alertLevel    = severityOrder.indexOf(alert.severity)

    const qualifying = recipients.filter(user => {
      const userLevel = severityOrder.indexOf(user.min_severity_for_email)
      return alertLevel >= userLevel
    })

    if (qualifying.length === 0) return
    await sendThreatAlert(alert, qualifying)
  } catch (err) {
    logger.warn(`⚠️  [Email] sendEmailAlerts failed: ${err.message}`)
  }
}

async function saveAndEmitAlert(io, alertData) {
  const severity = computeSeverity(alertData.probability)
  const newAlert = await Alert.create({
    source_ip:        alertData.source_ip,
    probability:      alertData.probability,
    threat_type:      alertData.threat_type || 'DDoS',
    features:         alertData.features    || {},
    severity,
    sensor_timestamp: alertData.sensor_timestamp
      ? new Date(alertData.sensor_timestamp)
      : new Date()
  })

  io.emit('ThreatDetected', {
    _id:        newAlert._id,
    source_ip:  newAlert.source_ip,
    probability: newAlert.probability,
    threat_type: newAlert.threat_type,
    severity:   newAlert.severity,
    createdAt:  newAlert.createdAt
  })
  logger.info(`📡 [Socket.io] ThreatDetected emitted | IP: ${newAlert.source_ip}`)

  sendEmailAlerts(newAlert).catch(err => logger.warn(`⚠️  [Email] ${err.message}`))
  trimAlerts().catch(err => logger.warn(`⚠️  [Cleanup] ${err.message}`))
  return newAlert
}

// ── POST /api/internal/alert ─────────────────────────────────────────────────

router.post('/internal/alert', validateSecret, async (req, res) => {
  const result = internalAlertSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({
      message: 'Validation failed',
      errors:  result.error.flatten().fieldErrors
    })
  }

  const { source_ip, probability, threat_type, features, timestamp } = result.data
  try {
    const io       = req.app.get('io')
    const newAlert = await saveAndEmitAlert(io, {
      source_ip, probability, threat_type, features, sensor_timestamp: timestamp
    })
    return res.status(201).json({ success: true, message: 'Alert logged', id: newAlert._id })
  } catch (err) {
    logger.error(`❌ [Alert] Save failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

// ── POST /api/internal/stats ─────────────────────────────────────────────────

router.post('/internal/stats', validateSecret, (req, res) => {
  const result = statsSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors:  result.error.flatten().fieldErrors
    })
  }

  const { window_number, total_packets, total_flows, timestamp, mode } = result.data
  req.app.get('io').emit('LiveStats', { window_number, total_packets, total_flows, timestamp, mode })
  return res.status(200).json({ success: true })
})

// ── GET /api/alerts ───────────────────────────────────────────────────────────

router.get('/alerts', async (req, res) => {
  try {
    const alerts = await Alert
      .find()
      .sort({ createdAt: -1 })
      .limit(MAX_STORED_ALERTS)
      .select('-features')
      .lean()
    return res.status(200).json({ success: true, count: alerts.length, data: alerts })
  } catch (err) {
    logger.error(`❌ [Alerts] Fetch failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

// ── POST /api/predict/manual ──────────────────────────────────────────────────

router.post('/predict/manual', requireAuth, manualPredictLimiter, async (req, res) => {
  const result = manualPredictSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors:  result.error.flatten().fieldErrors
    })
  }

  const { features } = result.data
  const userId = req.user?.userId || req.user?.email || 'unknown'
  logger.info(`🔍 [Manual] Prediction requested by ${userId}`)

  const pythonScript = path.join(__dirname, '..', '..', 'sensor', 'predict_manual.py')
  const pythonPath   = process.env.PYTHON_PATH ||
    (process.platform === 'win32'
      ? path.join(__dirname, '..', '..', '.venv', 'Scripts', 'python.exe')
      : path.join(__dirname, '..', '..', '.venv', 'bin', 'python'))

  const python = spawn(pythonPath, [pythonScript])
  let result_str = ''
  let error_str  = ''

  const timeout = setTimeout(() => {
    python.kill()
    logger.warn('⚠️  [Manual] Python process timed out')
    if (!res.headersSent) {
      return res.status(504).json({ success: false, message: 'ML prediction timed out' })
    }
  }, 15000)

  python.stdin.write(JSON.stringify(features))
  python.stdin.end()

  python.stdout.on('data', (data) => { result_str += data.toString() })
  python.stderr.on('data', (data) => { error_str  += data.toString() })

  python.on('close', async (code) => {
    clearTimeout(timeout)
    if (res.headersSent) return

    if (code !== 0) {
      logger.error(`❌ [Manual] Python exited ${code}: ${error_str}`)
      return res.status(500).json({ success: false, message: 'ML prediction failed', error: error_str })
    }

    try {
      const prediction = JSON.parse(result_str.trim())
      logger.info(`✅ [Manual] Result: ${prediction.label} | ${prediction.probability}%`)

      if (prediction.is_threat) {
        const io = req.app.get('io')
        await saveAndEmitAlert(io, {
          source_ip:   `MANUAL:${userId}`,
          probability: prediction.probability,
          threat_type: 'Manual-Test',
          features
        })
      }

      return res.status(200).json({
        success:     true,
        prediction:  prediction.prediction,
        probability: prediction.probability,
        label:       prediction.label,
        saved:       prediction.is_threat
      })
    } catch (parseErr) {
      logger.error(`❌ [Manual] Parse failed: ${result_str}`)
      return res.status(500).json({ success: false, message: 'Failed to parse prediction result' })
    }
  })

  python.on('error', (err) => {
    clearTimeout(timeout)
    logger.error(`❌ [Manual] Spawn failed: ${err.message}`)
    if (!res.headersSent) {
      return res.status(500).json({
        success: false,
        message: 'Failed to start Python process',
        error:   err.message
      })
    }
  })
})

module.exports = router