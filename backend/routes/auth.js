const express  = require('express')
const jwt      = require('jsonwebtoken')
const router   = express.Router()

const User           = require('../models/User')
const requireAuth    = require('../middleware/requireAuth')
const { authLoginLimiter, authRegisterLimiter } = require('../middleware/rateLimiter')
const { registerSchema, loginSchema, updateProfileSchema } = require('../schemas/alertSchemas')
const { sendVerificationEmail }       = require('../services/emailService')
const logger                          = require('../logger')
const { OAuth2Client }                = require('google-auth-library')

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID)

const cookieOptions = {
  httpOnly: true,
  secure:   process.env.NODE_ENV === 'production',
  // SameSite=none required for cross-domain cookies (Netlify → Render)
  // Must be 'strict' in development since we're on the same origin
  sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
  maxAge:   7 * 24 * 60 * 60 * 1000
}

router.post('/register', authRegisterLimiter, async (req, res) => {
  const result = registerSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({ success: false, message: 'Validation failed', errors: result.error.flatten().fieldErrors })
  }

  const { name, email, password } = result.data

  try {
    const existing = await User.findOne({ email })
    if (existing) {
      return res.status(409).json({ success: false, message: 'An account with this email already exists' })
    }

    const user = await User.create({ name, email, password })
    logger.info(`✅ [Auth] New user registered: ${email} (${user.userId})`)

    sendVerificationEmail(email, user._id).catch(err =>
      logger.warn(`⚠️  [Auth] Verification email failed: ${err.message}`)
    )

    return res.status(201).json({ success: true, message: 'Account created. Please check your email to verify your account.' })
  } catch (err) {
    logger.error(`❌ [Auth] Register failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

router.post('/login', authLoginLimiter, async (req, res) => {
  const result = loginSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({ success: false, message: 'Validation failed', errors: result.error.flatten().fieldErrors })
  }

  const { email, password } = result.data

  try {
    const user = await User.findOne({ email }).select('+password')
    if (!user) return res.status(401).json({ success: false, message: 'Invalid email or password' })
    if (!user.verified) return res.status(401).json({ success: false, message: 'Please verify your email before logging in' })

    const isMatch = await user.comparePassword(password)
    if (!isMatch) return res.status(401).json({ success: false, message: 'Invalid email or password' })

    const token = jwt.sign(
      { id: user._id, userId: user.userId, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'nids-soc-development-secret',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    )

    res.cookie('token', token, cookieOptions)
    logger.info(`✅ [Auth] Login: ${email}`)

    return res.status(200).json({
      success: true,
      user: { id: user._id, userId: user.userId, name: user.name, email: user.email, role: user.role }
    })
  } catch (err) {
    logger.error(`❌ [Auth] Login failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

router.post('/google', async (req, res) => {
  const { credential } = req.body
  if (!credential) return res.status(400).json({ success: false, message: 'No Google credential provided' })

  try {
    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    })
    
    const payload = ticket.getPayload()
    const { email, name, email_verified } = payload

    if (!email_verified) {
      return res.status(401).json({ success: false, message: 'Google account is not verified' })
    }

    let user = await User.findOne({ email })

    if (!user) {
      // Create user with a secure random password since they use Google to auth
      const randomPassword = require('crypto').randomBytes(32).toString('hex')
      user = await User.create({
        name,
        email,
        password: randomPassword,
        verified: true // Google already verified them
      })
      logger.info(`✅ [Auth] New user registered via Google: ${email} (${user.userId})`)
    }

    const token = jwt.sign(
      { id: user._id, userId: user.userId, email: user.email, role: user.role },
      process.env.JWT_SECRET || 'nids-soc-development-secret',
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    )

    res.cookie('token', token, cookieOptions)
    logger.info(`✅ [Auth] Google Login: ${email}`)

    return res.status(200).json({
      success: true,
      user: { id: user._id, userId: user.userId, name: user.name, email: user.email, role: user.role }
    })
  } catch (err) {
    logger.error(`❌ [Auth] Google Login failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Google authentication failed' })
  }
})

router.post('/logout', (req, res) => {
  res.clearCookie('token')
  logger.info('✅ [Auth] User logged out')
  return res.status(200).json({ success: true, message: 'Logged out' })
})

router.get('/me', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
    if (!user) return res.status(404).json({ success: false, message: 'User not found' })

    return res.status(200).json({
      success: true,
      user: {
        id: user._id, userId: user.userId, name: user.name, email: user.email, role: user.role,
        email_notifications: user.email_notifications, min_severity_for_email: user.min_severity_for_email
      }
    })
  } catch (err) {
    logger.error(`❌ [Auth] Me failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

router.patch('/me', requireAuth, async (req, res) => {
  const result = updateProfileSchema.safeParse(req.body)
  if (!result.success) {
    return res.status(400).json({ success: false, message: 'Validation failed', errors: result.error.flatten().fieldErrors })
  }

  try {
    const user = await User.findByIdAndUpdate(req.user.id, { $set: result.data }, { new: true })
    if (!user) return res.status(404).json({ success: false, message: 'User not found' })

    logger.info(`✅ [Auth] Profile updated: ${user.email}`)
    return res.status(200).json({
      success: true,
      user: {
        id: user._id, userId: user.userId, name: user.name, email: user.email, role: user.role,
        email_notifications: user.email_notifications, min_severity_for_email: user.min_severity_for_email
      }
    })
  } catch (err) {
    logger.error(`❌ [Auth] Profile update failed: ${err.message}`)
    return res.status(500).json({ success: false, message: 'Internal server error' })
  }
})

router.get('/verify', async (req, res) => {
  const { token } = req.query
  if (!token) return res.status(400).send(verifyHTML('Invalid Link', 'No verification token provided.', false))

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'nids-soc-development-secret')
    if (decoded.purpose !== 'verify-email') return res.status(400).send(verifyHTML('Invalid Link', 'This link is not a verification link.', false))

    const user = await User.findById(decoded.id)
    if (!user) return res.status(404).send(verifyHTML('Not Found', 'Account not found.', false))

    if (user.verified) return res.send(verifyHTML('Already Verified', 'Your email is already verified. You can log in.', true))

    user.verified = true
    await user.save()
    logger.info(`✅ [Auth] Email verified: ${user.email}`)
    return res.send(verifyHTML('Email Verified!', 'Your account is now active. You can close this tab and log in.', true))
  } catch (err) {
    logger.warn(`⚠️  [Auth] Verify failed: ${err.message}`)
    return res.status(400).send(verifyHTML('Link Expired', 'This verification link has expired. Please register again.', false))
  }
})

router.get('/unsubscribe', async (req, res) => {
  const { token } = req.query
  const frontendUrl = process.env.CLIENT_URL_PROD || process.env.CLIENT_URL_DEV || 'http://localhost:5173'

  if (!token) return res.redirect(`${frontendUrl}/unsubscribed?error=invalid`)

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'nids-soc-development-secret')
    if (decoded.purpose !== 'unsubscribe') return res.redirect(`${frontendUrl}/unsubscribed?error=invalid`)

    await User.findByIdAndUpdate(decoded.id, { min_severity_for_email: 'NONE' })
    logger.info(`✅ [Auth] User unsubscribed via email link: ${decoded.id}`)
    
    return res.redirect(`${frontendUrl}/unsubscribed?success=true`)
  } catch (err) {
    logger.warn(`⚠️  [Auth] Unsubscribe failed: ${err.message}`)
    return res.redirect(`${frontendUrl}/unsubscribed?error=expired`)
  }
})

function verifyHTML(title, message, success) {
  const dashboardLink = process.env.CLIENT_URL_PROD || process.env.CLIENT_URL_DEV
  const color = success ? '#22c55e' : '#ef4444'
  const emoji = success ? '✅' : '❌'
  return `
    <!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>${title} — NIDS SOC</title></head>
    <body style="margin:0;padding:0;background-color:#0f172a;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;">
      <div style="max-width:480px;width:100%;padding:24px;">
        <div style="background-color:#1e293b;border:1px solid #334155;border-radius:12px;padding:32px;text-align:center;">
          <div style="font-size:48px;margin-bottom:16px;">🛡️</div>
          <h1 style="color:#ffffff;font-size:20px;margin:0 0 8px;">NIDS SOC Dashboard</h1>
          <div style="width:40px;height:2px;background:${color};margin:16px auto;border-radius:2px;"></div>
          <div style="font-size:32px;margin-bottom:12px;">${emoji}</div>
          <h2 style="color:${color};font-size:18px;margin:0 0 12px;">${title}</h2>
          <p style="color:#94a3b8;font-size:14px;line-height:1.6;margin:0 0 24px;">${message}</p>
          <a href="${dashboardLink}" style="display:inline-block;background-color:#2563eb;color:#ffffff;text-decoration:none;padding:10px 24px;border-radius:8px;font-size:14px;">Go to Dashboard →</a>
        </div>
      </div>
    </body></html>`
}

module.exports = router