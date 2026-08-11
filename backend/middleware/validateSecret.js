const crypto = require('crypto')
const logger = require('../logger')

const validateSecret = (req, res, next) => {
  const incoming = req.headers['x-sensor-secret']

  if (!incoming) {
    logger.warn('❌ Sensor: missing X-Sensor-Secret header')
    return res.status(401).json({ success: false, message: 'Unauthorized' })
  }

  try {
    const expected = Buffer.from(process.env.SENSOR_SECRET || '')
    const received = Buffer.from(incoming)

    if (expected.length !== received.length) {
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    if (!crypto.timingSafeEqual(expected, received)) {
      logger.warn('❌ Sensor: invalid secret')
      return res.status(401).json({ success: false, message: 'Unauthorized' })
    }

    next()
  } catch (err) {
    logger.error(`❌ Secret validation error: ${err.message}`)
    return res.status(401).json({ success: false, message: 'Unauthorized' })
  }
}

module.exports = validateSecret