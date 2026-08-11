const express  = require('express')
const router   = express.Router()

const Blocklist   = require('../models/Blocklist')
const Alert       = require('../models/Alert')
const logger      = require('../logger')
const requireAuth    = require('../middleware/requireAuth')
const validateSecret = require('../middleware/validateSecret')
const blockedIPsCache = require('../cache')
const { blockIPSchema, unblockIPSchema } = require('../schemas/alertSchemas')
const { blockIPLimiter } = require('../middleware/rateLimiter')

router.get('/ips', validateSecret, (req, res) => {
  return res.status(200).json({ success: true, ips: Array.from(blockedIPsCache) })
})

router.get('/', async (req, res) => {
  try {
    const blocklist = await Blocklist.find().sort({ createdAt: -1 }).lean()
    return res.status(200).json({ success: true, count: blocklist.length, data: blocklist })
  } catch (err) {
    logger.error(`❌ [Blocklist] Fetch failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

router.post('/block', requireAuth, blockIPLimiter, async (req, res) => {
  const result = blockIPSchema.safeParse(req.body)
  if (!result.success) return res.status(400).json({ success: false, message: 'Validation failed', errors: result.error.flatten().fieldErrors })

  const { ip, reason } = result.data

  if (blockedIPsCache.has(ip)) return res.status(409).json({ success: false, message: `${ip} is already blocked` })

  try {
    const entry = await Blocklist.create({ ip, blockedBy: req.user.userId || 'System', reason: reason || '' })
    blockedIPsCache.add(ip)
    await Alert.updateMany({ source_ip: ip }, { $set: { blocked: true } })

    const io = req.app.get('io')
    io.emit('IPBlocked', { ip, blockedBy: req.user.userId || 'System', createdAt: entry.createdAt })
    logger.info(`🚫 [Blocklist] ${ip} blocked by ${req.user.userId}`)

    return res.status(201).json({ success: true, message: `${ip} has been blocked`, data: entry })
  } catch (err) {
    logger.error(`❌ [Blocklist] Block failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

router.post('/unblock', requireAuth, async (req, res) => {
  const result = unblockIPSchema.safeParse(req.body)
  if (!result.success) return res.status(400).json({ success: false, message: 'Validation failed', errors: result.error.flatten().fieldErrors })

  const { ip } = result.data
  if (!blockedIPsCache.has(ip)) return res.status(404).json({ success: false, message: `${ip} is not currently blocked` })

  try {
    await Blocklist.deleteOne({ ip })
    blockedIPsCache.delete(ip)
    await Alert.updateMany({ source_ip: ip }, { $set: { blocked: false } })

    const io = req.app.get('io')
    io.emit('IPUnblocked', { ip })
    logger.info(`✅ [Blocklist] ${ip} unblocked by ${req.user.userId}`)

    return res.status(200).json({ success: true, message: `${ip} has been unblocked` })
  } catch (err) {
    logger.error(`❌ [Blocklist] Unblock failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

module.exports = router