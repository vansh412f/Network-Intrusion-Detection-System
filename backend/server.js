require('dotenv').config({ path: '../.env' })

const express      = require('express')
const http         = require('http')
const cors         = require('cors')
const mongoose     = require('mongoose')
const helmet       = require('helmet')
const morgan       = require('morgan')
const cookieParser = require('cookie-parser')
const { Server }   = require('socket.io')

const logger = require('./logger')

const blockedIPsCache = require('./cache')

const Alert     = require('./models/Alert')
const User      = require('./models/User')
const Blocklist = require('./models/Blocklist')

const alertRoutes     = require('./routes/alert')
const authRoutes      = require('./routes/auth')
const blocklistRoutes = require('./routes/blocklist')
const { verifyTransporter } = require('./services/emailService')

// DEMO BLOCKLIST CONFIG 

const DEMO_BLOCKED_IPS = [
  { ip: '45.33.32.156',   reason: 'Suspicious scan activity' },
  { ip: '185.220.101.34', reason: 'Known Tor exit node' },
  { ip: '23.129.64.210',  reason: 'Repeated brute-force attempts' }
]

const DEMO_SEED_INTERVAL_MS = 25 * 60 * 1000  // 25 minutes (before 30 min TTL)

// EXPRESS SETUP 

const app = express()

app.set('blockedIPsCache', blockedIPsCache)

app.use(helmet())

const allowedOrigins = [
  process.env.CLIENT_URL_DEV,
  process.env.CLIENT_URL_PROD
].filter(Boolean)

app.use(cors({
  origin: (origin, callback) => {
    if (!origin) return callback(null, true)
    if (allowedOrigins.includes(origin)) return callback(null, true)
    callback(new Error(`CORS blocked: ${origin}`))
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  credentials: true
}))

app.use(express.json())
app.use(cookieParser())
app.use(morgan('combined', { stream: logger.stream }))

// HTTP + SOCKET.IO 

const httpServer = http.createServer(app)

const io = new Server(httpServer, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  }
})

io.on('connection', (socket) => {
  logger.info(`📡 [Socket.io] Client connected    | ID: ${socket.id}`)
  socket.on('disconnect', () => {
    logger.info(`📡 [Socket.io] Client disconnected | ID: ${socket.id}`)
  })
})

app.set('io', io)

// DATABASE 

const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI)
    logger.info(`✅ [MongoDB] Connected | Host: ${conn.connection.host} | DB: ${conn.connection.name}`)
  } catch (error) {
    logger.error(`❌ [MongoDB] Connection failed: ${error.message}`)
    process.exit(1)
  }
}

// DEMO SEED FUNCTION 

async function seedDemoBlocklist() {
  try {
    const ops = DEMO_BLOCKED_IPS.map(({ ip, reason }) => ({
      updateOne: {
        filter: { ip },
        update: {
          $set: { ip, blockedBy: 'System', reason },
          $setOnInsert: { createdAt: new Date() }
        },
        upsert: true
      }
    }))

    const result = await Blocklist.bulkWrite(ops)
    const upserted = result.upsertedCount || 0
    const modified = result.modifiedCount || 0

    // Sync cache
    DEMO_BLOCKED_IPS.forEach(({ ip }) => blockedIPsCache.add(ip))

    if (upserted > 0 || modified > 0) {
      logger.info(`🔄 [Demo] Blocklist refreshed | New: ${upserted}, Refreshed: ${modified}`)
    }
  } catch (err) {
    logger.warn(`⚠️  [Demo] Blocklist seed failed: ${err.message}`)
  }
}

// PERIODIC EXPIRATION SYNC

async function syncBlocklistExpirations() {
  try {
    const activeBlocks = await Blocklist.find().select('ip').lean()
    const activeIPs = new Set(activeBlocks.map(b => b.ip))

    for (const cachedIP of blockedIPsCache) {
      // If the IP is in cache but no longer in the DB, it expired via TTL
      if (!activeIPs.has(cachedIP)) {
        blockedIPsCache.delete(cachedIP)
        
        // Update historical alerts to reflect the unblock
        await Alert.updateMany({ source_ip: cachedIP }, { $set: { blocked: false } })
        
        // Notify all connected frontends
        io.emit('IPUnblocked', { ip: cachedIP })
        logger.info(`✅ [Blocklist] ${cachedIP} automatically unblocked (TTL expired)`)
      }
    }
  } catch (err) {
    logger.warn(`⚠️  [Blocklist] Expiration sync failed: ${err.message}`)
  }
}

// ROUTES 

app.get('/health', (req, res) => {
  res.json({
    status:   'ok',
    server:   'NIDS SOC Backend',
    time:     new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  })
})

app.use('/api/auth',      authRoutes)
app.use('/api',           alertRoutes)
app.use('/api/blocklist', blocklistRoutes)

// ERROR HANDLER 

app.use((err, req, res, next) => {
  logger.error(`❌ [Error] ${err.message}`)
  res.status(err.status || 500).json({
    success: false,
    message: process.env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message
  })
})

// GRACEFUL SHUTDOWN 

const gracefulShutdown = async (signal) => {
  logger.info(`⚠️  [Server] ${signal} received — shutting down gracefully`)
  httpServer.close(async () => {
    try {
      await mongoose.connection.close()
      logger.info('✅ [Server] MongoDB connection closed — process exiting')
      process.exit(0)
    } catch (err) {
      logger.error(`❌ [Server] Error during shutdown: ${err.message}`)
      process.exit(1)
    }
  })
}

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'))
process.on('SIGINT',  () => gracefulShutdown('SIGINT'))

// START SERVER 

const PORT = process.env.PORT || 3000

const startServer = async () => {
  await connectDB()

  // Verify SMTP transporter
  try {
    await verifyTransporter()
  } catch (err) {
    logger.warn(`⚠️  [Email] SMTP verification failed: ${err.message}`)
  }

  // Load existing blocked IPs into cache
  try {
    const docs = await Blocklist.find().select('ip')
    docs.forEach(doc => blockedIPsCache.add(doc.ip))
    logger.info(`✅ [Blocklist] Loaded ${docs.length} blocked IP(s) into cache`)
  } catch (err) {
    logger.warn(`⚠️  [Blocklist] Failed to load cache: ${err.message}`)
  }

  // Seed demo blocklist immediately + refresh every 25 min (before TTL)
  await seedDemoBlocklist()
  setInterval(seedDemoBlocklist, DEMO_SEED_INTERVAL_MS)

  // Sync TTL expirations every 15 seconds
  setInterval(syncBlocklistExpirations, 15 * 1000)

  httpServer.listen(PORT, () => {
    logger.info('══════════════════════════════════════════════════')
    logger.info('  NIDS SOC BACKEND RUNNING')
    logger.info('══════════════════════════════════════════════════')
    logger.info(`  Server  → http://localhost:${PORT}`)
    logger.info(`  Health  → http://localhost:${PORT}/health`)
    logger.info(`  Mode    → ${process.env.NODE_ENV}`)
    logger.info('══════════════════════════════════════════════════')
  })
}

startServer()