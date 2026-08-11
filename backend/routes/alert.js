const express  = require('express')
const router   = express.Router()
const path     = require('path')
const { spawn } = require('child_process')
const readline = require('readline')

const Alert       = require('../models/Alert')
const User        = require('../models/User')
const logger      = require('../logger')
const requireAuth = require('../middleware/requireAuth')
const validateSecret          = require('../middleware/validateSecret')
const { manualPredictLimiter } = require('../middleware/rateLimiter')
const { internalAlertSchema, manualPredictSchema, statsSchema } = require('../schemas/alertSchemas')
const { sendThreatAlert } = require('../services/emailService')

class AsyncQueue {
  constructor() {
    this.queue = [];
    this.isProcessing = false;
  }
  async add(task) {
    return new Promise((resolve, reject) => {
      this.queue.push(async () => {
        try { resolve(await task()); } 
        catch (err) { reject(err); }
      });
      this.process();
    });
  }
  async process() {
    if (this.isProcessing || this.queue.length === 0) return;
    this.isProcessing = true;
    const task = this.queue.shift();
    await task();
    this.isProcessing = false;
    this.process();
  }
}

const predictQueue = new AsyncQueue();

let persistentPython = null;
let currentResolve = null;
let currentReject  = null;

function getPersistentPython() {
  if (persistentPython && !persistentPython.killed) {
    return persistentPython;
  }

  const pythonScript = path.join(__dirname, '..', '..', 'sensor', 'predict_manual.py');
  const pythonPath   = process.env.PYTHON_PATH ||
    (process.platform === 'win32'
      ? path.join(__dirname, '..', '..', '.venv', 'Scripts', 'python.exe')
      : path.join(__dirname, '..', '..', '.venv', 'bin', 'python'));

  persistentPython = spawn(pythonPath, [pythonScript]);
  const rl = readline.createInterface({ input: persistentPython.stdout });

  rl.on('line', (line) => {
    try {
      const parsed = JSON.parse(line.trim());
      if (parsed.status === 'ready') {
        logger.info('✅ [Manual] Python daemon ready');
        return;
      }
      if (currentResolve) {
        if (parsed.error) currentReject(new Error(parsed.error));
        else currentResolve(parsed);
      }
    } catch (err) {
      if (currentReject) currentReject(new Error(`Parse error: ${line}`));
    }
  });

  persistentPython.stderr.on('data', (data) => {
    logger.warn(`⚠️  [Manual Python] ${data.toString().trim()}`);
  });

  persistentPython.on('error', (err) => {
    logger.error(`❌ [Manual] Persistent Python daemon error: ${err.message}`);
    persistentPython = null;
    if (currentReject) { currentReject(err); currentReject = null; currentResolve = null; }
  });

  persistentPython.on('exit', (code) => {
    logger.warn(`⚠️  [Manual] Persistent Python daemon exited with code ${code}`);
    persistentPython = null;
    if (currentReject) { currentReject(new Error(`Python exited with code ${code}`)); currentReject = null; currentResolve = null; }
  });

  return persistentPython;
}

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

  try {
    const prediction = await predictQueue.add(() => {
      return new Promise((resolve, reject) => {
        const python = getPersistentPython()
        
        const timeout = setTimeout(() => {
          python.kill()
          persistentPython = null
          const err = new Error('ML prediction timed out')
          if (currentReject) currentReject(err)
        }, 15000)

        currentResolve = (data) => {
          clearTimeout(timeout)
          currentResolve = null
          currentReject = null
          resolve(data)
        }

        currentReject = (err) => {
          clearTimeout(timeout)
          currentResolve = null
          currentReject = null
          reject(err)
        }

        python.stdin.write(JSON.stringify(features) + '\n')
      })
    })

    logger.info(`✅ [Manual] Result: ${prediction.label} | ${prediction.probability}%`)

    if (prediction.is_threat) {
      const io = req.app.get('io')
      await saveAndEmitAlert(io, {
        source_ip:   'MANUAL',
        probability: prediction.probability,
        threat_type: 'MANUAL',
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

  } catch (err) {
    logger.error(`❌ [Manual] Prediction failed: ${err.message}`)
    if (err.message.includes('timed out')) {
      return res.status(504).json({ success: false, message: 'ML prediction timed out. Please try again.' })
    }
    return res.status(500).json({ success: false, message: 'ML prediction failed', error: err.message })
  }
})

module.exports = router