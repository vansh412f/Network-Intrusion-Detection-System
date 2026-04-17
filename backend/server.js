/**
 * ================================================================================
 * NIDS SOC Backend Server
 * ================================================================================
 * 
 * Purpose:
 *   - REST API for threat alerts and statistics
 *   - Socket.io real-time communication with React dashboard
 *   - MongoDB persistence for threat logs
 * 
 * Tech Stack:
 *   - Express.js (REST API)
 *   - Socket.io (WebSocket communication)
 *   - MongoDB + Mongoose (Database)
 * 
 * Environment Variables:
 *   - MONGO_URI: MongoDB connection string
 *   - CLIENT_URL: Frontend URL for CORS (default: http://localhost:5173)
 *   - PORT: Server port (default: 3000)
 *   - SENSOR_SECRET: Secret key for sensor authentication
 * 
 * ================================================================================
 */

require('dotenv').config();

const express   = require('express');
const http      = require('http');
const cors      = require('cors');
const mongoose  = require('mongoose');
const { Server } = require('socket.io');

const app = express();


// ══════════════════════════════════════════════════════════════════════════════
// MIDDLEWARE
// ══════════════════════════════════════════════════════════════════════════════

app.use(express.json());

// CORS configuration for React frontend
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  methods: ['GET', 'POST'],
  credentials: true
}));


// ══════════════════════════════════════════════════════════════════════════════
// HTTP SERVER + SOCKET.IO SETUP
// ══════════════════════════════════════════════════════════════════════════════

const httpServer = http.createServer(app);

const io = new Server(httpServer, {
  cors: {
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Socket.io connection event handlers
io.on('connection', (socket) => {
  console.log(`[Socket.io] ✅ Client connected    | ID: ${socket.id}`);

  socket.on('disconnect', () => {
    console.log(`[Socket.io] ❌ Client disconnected | ID: ${socket.id}`);
  });
});

// Make Socket.io instance available to routes
app.set('io', io);


// ══════════════════════════════════════════════════════════════════════════════
// MONGODB CONNECTION
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Connects to MongoDB Atlas using URI from environment variables.
 * Exits process if connection fails.
 */
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);

    console.log(`[MongoDB]   ✅ Connected`);
    console.log(`            Host: ${conn.connection.host}`);
    console.log(`            DB:   ${conn.connection.name}`);

  } catch (error) {
    console.error(`[MongoDB]   ❌ Connection failed: ${error.message}`);
    process.exit(1);
  }
};


// ══════════════════════════════════════════════════════════════════════════════
// ROUTES
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /health
 * Health check endpoint for monitoring/deployment.
 */
app.get('/health', (req, res) => {
  res.json({
    status:   'ok',
    server:   'NIDS SOC Backend',
    time:     new Date().toISOString(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// Mount alert routes (defined in routes/alert.js)
const alertRoutes = require('./routes/alert');
app.use('/api', alertRoutes);


// ══════════════════════════════════════════════════════════════════════════════
// SERVER STARTUP
// ══════════════════════════════════════════════════════════════════════════════

const PORT = process.env.PORT || 3000;

const startServer = async () => {
  // Connect to MongoDB first
  await connectDB();

  // Start HTTP server
  httpServer.listen(PORT, () => {
    console.log('');
    console.log('='.repeat(50));
    console.log('  NIDS SOC BACKEND RUNNING');
    console.log('='.repeat(50));
    console.log(`  Server    → http://localhost:${PORT}`);
    console.log(`  Health    → http://localhost:${PORT}/health`);
    console.log(`  Alerts    → http://localhost:${PORT}/api/alerts`);
    console.log(`  Receiver  → http://localhost:${PORT}/api/internal/alert`);
    console.log('='.repeat(50));
    console.log('');
  });
};

startServer();