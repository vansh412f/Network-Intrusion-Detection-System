const winston = require('winston')

const { combine, timestamp, printf, colorize, json } = winston.format

const isProduction = process.env.NODE_ENV === 'production'

// Pretty console format for development
const devFormat = printf(({ level, message, timestamp }) => {
  return `[${timestamp}] ${level}: ${message}`
})

const logger = winston.createLogger({
  level: isProduction ? 'info' : 'debug',
  format: isProduction
    ? combine(
        timestamp(),
        json()
      )
    : combine(
        timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
        colorize(),
        devFormat
      ),
  transports: [
    new winston.transports.Console()
  ]
})

// Morgan stream support (HTTP request logging)
logger.stream = {
  write: (message) => {
    logger.info(message.trim())
  }
}

module.exports = logger