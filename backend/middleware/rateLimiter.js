const rateLimit = require('express-rate-limit')

function rateLimitHandler(_req, res) {
  res.status(429).json({
    success: false,
    message: 'Too many requests. Please try again later.'
  })
}

const manualPredictLimiter = rateLimit({
  windowMs:        15 * 60 * 1000,
  max:             10,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         rateLimitHandler,
  message:         { success: false, message: 'Prediction limit reached (10 per 15 minutes).' }
})

const authLoginLimiter = rateLimit({
  windowMs:               15 * 60 * 1000,
  max:                    10,
  standardHeaders:        true,
  legacyHeaders:          false,
  skipSuccessfulRequests: true,
  handler:                rateLimitHandler,
  message:                { success: false, message: 'Too many login attempts. Try again in 15 minutes.' }
})

const authRegisterLimiter = rateLimit({
  windowMs:        60 * 60 * 1000,
  max:             2,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         rateLimitHandler,
  message:         { success: false, message: 'Too many registration attempts. Try again in 1 hour.' }
})

// Max 3 blocks per 30 minutes per user IP
const blockIPLimiter = rateLimit({
  windowMs:        30 * 60 * 1000,
  max:             3,
  standardHeaders: true,
  legacyHeaders:   false,
  handler:         rateLimitHandler,
  message:         { success: false, message: 'Demo limit reached — maximum 3 blocks per 30 minutes' }
})

module.exports = {
  manualPredictLimiter,
  authLoginLimiter,
  authRegisterLimiter,
  blockIPLimiter
}