const jwt    = require('jsonwebtoken')
const logger = require('../logger')

/**
 * Verifies JWT from httpOnly cookie.
 * Attaches decoded payload to req.user on success.
 * Returns 401 if token is missing, invalid, or expired.
 */
const requireAuth = (req, res, next) => {
  const token = req.cookies?.token

  if (!token) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required'
    })
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET)

    // Attach user payload to request for downstream route handlers
    // decoded = { id, email, role, iat, exp }
    req.user = decoded

    next()
  } catch (err) {
    logger.warn(`⚠️  [Auth] Invalid token: ${err.message}`)

    return res.status(401).json({
      success: false,
      message: 'Session expired — please log in again'
    })
  }
}

module.exports = requireAuth