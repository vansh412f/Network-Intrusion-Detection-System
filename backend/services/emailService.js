const axios = require('axios')
const jwt   = require('jsonwebtoken')
const logger = require('../logger')

// The Google Apps Script Web App URL
const GOOGLE_SCRIPT_URL = process.env.GOOGLE_SCRIPT_URL

async function verifyTransporter() {
  if (!GOOGLE_SCRIPT_URL) {
    throw new Error('GOOGLE_SCRIPT_URL must be set to send emails via Apps Script')
  }
  logger.info('✅ [Email] Google Apps Script URL configured')
}

function getBackendUrl() {
  if (process.env.NODE_ENV === 'production') {
    return 'https://network-intrusion-detection-system-7mh6.onrender.com'
  }
  return `http://localhost:${process.env.PORT || 3000}`
}

const SEVERITY_COLORS = { LOW: '#eab308', MEDIUM: '#f97316', HIGH: '#ef4444', CRITICAL: '#b91c1c' }
const SEVERITY_EMOJI  = { LOW: '🟡', MEDIUM: '🟠', HIGH: '🔴', CRITICAL: '🚨' }

// Track last email sent time per user to prevent spam and hitting 100/day limits
const lastEmailSentAt = new Map()
const ALERT_COOLDOWN_MS = 15 * 60 * 1000 // 15 minutes cooldown per user

function generateUnsubscribeToken(userId) {
  return jwt.sign(
    { id: userId, purpose: 'unsubscribe' },
    process.env.JWT_SECRET || 'nids-soc-development-secret',
    { expiresIn: '30d' }
  )
}

async function sendThreatAlert(alert, recipients) {
  if (!GOOGLE_SCRIPT_URL || !recipients?.length) return

  const severity      = alert.severity || 'LOW'
  const color         = SEVERITY_COLORS[severity]
  const emoji         = SEVERITY_EMOJI[severity]
  const dashboardLink = process.env.CLIENT_URL_PROD || process.env.CLIENT_URL_DEV
  const backendUrl    = getBackendUrl()
  const subject       = `${emoji} NIDS ${severity} Alert — ${alert.threat_type} Detected`

  const sendPromises = recipients.map(async (user) => {
    // RATE LIMITING: Check if user received an email in the last 15 minutes
    const lastSent = lastEmailSentAt.get(user._id.toString())
    if (lastSent && (Date.now() - lastSent < ALERT_COOLDOWN_MS)) {
      logger.info(`⏳ [Email] Skipped alert for ${user.email} (Cooldown active)`)
      return
    }

    const unsubscribeToken = generateUnsubscribeToken(user._id)
    const unsubscribeLink  = `${backendUrl}/api/auth/unsubscribe?token=${unsubscribeToken}`

    const html = `
      <!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
      <body style="margin:0;padding:0;background-color:#0f172a;font-family:monospace;">
        <div style="max-width:600px;margin:0 auto;padding:24px;">
          <div style="background-color:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:16px;">
            <div style="margin-bottom:16px;">
              <span style="font-size:28px;">⚠️</span>
              <h1 style="margin:4px 0 0;color:#ffffff;font-size:18px;">NIDS SOC Dashboard</h1>
              <p style="margin:0;color:#94a3b8;font-size:13px;">Threat Detection Alert</p>
            </div>
            <div style="background-color:${color}22;border:1px solid ${color};border-radius:8px;padding:12px 16px;margin-bottom:16px;">
              <p style="margin:0;color:${color};font-size:20px;font-weight:bold;">${emoji} ${severity} SEVERITY</p>
              <p style="margin:4px 0 0;color:#cbd5e1;font-size:13px;">${alert.threat_type} attack detected with ${alert.probability}% confidence</p>
            </div>
            <table style="width:100%;border-collapse:collapse;">
              <tr><td style="padding:8px 0;color:#94a3b8;font-size:13px;width:140px;">Source IP</td><td style="padding:8px 0;color:#ffffff;font-size:13px;font-weight:bold;">${alert.source_ip}</td></tr>
              <tr><td style="padding:8px 0;color:#94a3b8;font-size:13px;">Confidence</td><td style="padding:8px 0;color:#ffffff;font-size:13px;">${alert.probability}%</td></tr>
              <tr><td style="padding:8px 0;color:#94a3b8;font-size:13px;">Threat Type</td><td style="padding:8px 0;color:#ffffff;font-size:13px;">${alert.threat_type}</td></tr>
              <tr><td style="padding:8px 0;color:#94a3b8;font-size:13px;">Detected At</td><td style="padding:8px 0;color:#ffffff;font-size:13px;">${new Date(alert.createdAt).toUTCString()}</td></tr>
            </table>
          </div>
          <div style="text-align:center;margin-bottom:16px;">
            <a href="${dashboardLink}" style="display:inline-block;background-color:#2563eb;color:#ffffff;text-decoration:none;padding:12px 32px;border-radius:8px;font-size:14px;font-weight:bold;">View Dashboard →</a>
          </div>
          <div style="text-align:center;margin-bottom:24px;">
            <a href="${unsubscribeLink}" style="display:inline-block;background-color:transparent;color:#94a3b8;text-decoration:none;padding:10px 24px;border-radius:8px;font-size:12px;border:1px solid #334155;">Unsubscribe from Alerts</a>
          </div>
          <div style="text-align:center;border-top:1px solid #1e293b;padding-top:16px;">
            <p style="color:#64748b;font-size:12px;margin:0 0 8px;">⏱️ <strong>Smart Cooldown Active:</strong> To prevent inbox flooding during heavy attacks, you will receive maximum one alert every 15 minutes.</p>
            <p style="color:#475569;font-size:11px;margin:0;">NIDS SOC Dashboard · Powered by XGBoost · CIC-DDoS2019</p>
          </div>
        </div>
      </body></html>`

    try {
      await axios.post(GOOGLE_SCRIPT_URL, {
        to: user.email,
        subject,
        html
      }, {
        headers: { 'Content-Type': 'application/json' }
      })
      lastEmailSentAt.set(user._id.toString(), Date.now()) // Update cooldown timer
      logger.info(`✅ [Email] Alert sent to ${user.email} via Google Apps Script`)
    } catch (err) {
      logger.warn(`⚠️  [Email] Failed to send to ${user.email}: ${err.message}`)
    }
  })

  await Promise.allSettled(sendPromises)
}

async function sendVerificationEmail(email, userId) {
  if (!GOOGLE_SCRIPT_URL) return

  const token = jwt.sign(
    { id: userId, purpose: 'verify-email' },
    process.env.JWT_SECRET || 'nids-soc-development-secret',
    { expiresIn: '24h' }
  )
  const verifyLink    = `${getBackendUrl()}/api/auth/verify?token=${token}`
  const dashboardLink = process.env.CLIENT_URL_PROD || process.env.CLIENT_URL_DEV

  const html = `
    <!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"></head>
    <body style="margin:0;padding:0;background-color:#0f172a;font-family:monospace;">
      <div style="max-width:600px;margin:0 auto;padding:24px;">
        <div style="background-color:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:16px;">
          <div style="margin-bottom:20px;">
            <span style="font-size:28px;">🛡️</span>
            <h1 style="margin:4px 0 0;color:#ffffff;font-size:18px;">NIDS SOC Dashboard</h1>
            <p style="margin:0;color:#94a3b8;font-size:13px;">Email Verification</p>
          </div>
          <p style="color:#cbd5e1;font-size:14px;line-height:1.6;">Welcome! Please verify your email address to activate your analyst account. This link expires in 24 hours.</p>
          <div style="text-align:center;margin:24px 0;">
            <a href="${verifyLink}" style="display:inline-block;background-color:#2563eb;color:#ffffff;text-decoration:none;padding:12px 32px;border-radius:8px;font-size:14px;font-weight:bold;">Verify Email Address →</a>
          </div>
          <p style="color:#475569;font-size:12px;">If you did not create this account, ignore this email.</p>
        </div>
        <p style="text-align:center;color:#475569;font-size:11px;margin:0;">NIDS SOC Dashboard · Powered by XGBoost · CIC-DDoS2019</p>
      </div>
    </body></html>`

  try {
    await axios.post(GOOGLE_SCRIPT_URL, {
      to: email,
      subject: '🛡️ Verify your NIDS SOC Dashboard email',
      html
    }, {
      headers: { 'Content-Type': 'application/json' }
    })
    logger.info(`✅ [Email] Verification email sent to ${email} via Google Apps Script`)
  } catch (err) {
    logger.warn(`⚠️  [Email] Failed to send verification email: ${err.message}`)
  }
}

module.exports = { sendThreatAlert, sendVerificationEmail, verifyTransporter }