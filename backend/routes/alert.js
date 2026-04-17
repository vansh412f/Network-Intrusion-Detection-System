/**
 * ================================================================================
 * NIDS Alert Routes
 * ================================================================================
 * 
 * Endpoints:
 *   POST /api/internal/alert    ← Python sensor sends detected threats
 *   POST /api/internal/stats    ← Python sensor sends live traffic stats
 *   GET  /api/alerts            ← React dashboard fetches alert history
 *   POST /api/test/trigger-attack  ← Demo button (fake 99.8% alert)
 *   POST /api/predict/manual    ← Manual feature input (runs real ML model)
 * 
 * Authentication:
 *   - Internal endpoints require X-Sensor-Secret header
 *   - Secret must match SENSOR_SECRET environment variable
 * 
 * ================================================================================
 */

const express = require('express');
const router  = express.Router();
const { spawn } = require('child_process');
const path = require('path');
const Alert   = require('../models/Alert');

// ── DB Cleanup: keep only the latest 200 alerts ─────────────
// Called fire-and-forget after every alert save.
// Finds and deletes the oldest (count - 200) documents.
const MAX_STORED_ALERTS = 200;

async function trimAlerts() {
  const count = await Alert.countDocuments();
  if (count <= MAX_STORED_ALERTS) return;

  const excess  = count - MAX_STORED_ALERTS;
  const oldest  = await Alert.find()
    .sort({ createdAt: 1 })
    .limit(excess)
    .select('_id');

  await Alert.deleteMany({ _id: { $in: oldest.map(a => a._id) } });
  console.log(`[Cleanup] 🗑️  Removed ${excess} old alert(s) — keeping latest ${MAX_STORED_ALERTS}`);
}


// ══════════════════════════════════════════════════════════════════════════════
// INTERNAL ENDPOINT — THREAT ALERTS FROM SENSOR
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/internal/alert
 * 
 * Receives threat alerts from Python sensor (sensor.py).
 * Validates secret key, saves to MongoDB, emits Socket.io event.
 * 
 * Request Headers:
 *   X-Sensor-Secret: Authentication secret
 * 
 * Request Body:
 *   source_ip (string): Attacker IP address
 *   probability (number): ML confidence 0-100
 *   timestamp (string): ISO timestamp from sensor
 *   threat_type (string): Attack type (DDoS, PortScan, etc.)
 *   features (object): 15 network flow features
 * 
 * Response:
 *   201: Alert saved successfully
 *   400: Missing required fields
 *   401: Invalid secret key
 *   500: Database error
 */
router.post('/internal/alert', async (req, res) => {
  
  // Verify sensor authentication
  const sensorSecret = req.headers['x-sensor-secret'];
  
  if (sensorSecret !== process.env.SENSOR_SECRET) {
    console.log('[Alert]  ❌ Unauthorized alert attempt — wrong secret');
    return res.status(401).json({
      success: false,
      message: 'Unauthorized'
    });
  }

  // Extract and validate data
  const { source_ip, probability, timestamp, threat_type, features } = req.body;

  if (!source_ip || probability === undefined) {
    return res.status(400).json({
      success: false,
      message: 'source_ip and probability are required'
    });
  }

  console.log(`[Alert]  🚨 Threat received | IP: ${source_ip} | Confidence: ${probability}%`);

  // Save to MongoDB
  try {
    const newAlert = await Alert.create({
      source_ip,
      probability,
      threat_type:      threat_type || 'DDoS',
      features:         features    || {},
      sensor_timestamp: timestamp
    });

    console.log(`[Alert]  ✅ Saved to MongoDB | ID: ${newAlert._id}`);

    // Broadcast to all connected dashboards via Socket.io
    const io = req.app.get('io');
    io.emit('ThreatDetected', {
      _id:         newAlert._id,
      source_ip:   newAlert.source_ip,
      probability: newAlert.probability,
      threat_type: newAlert.threat_type,
      createdAt:   newAlert.createdAt
    });

    console.log(`[Alert]  📡 Socket.io event emitted → ThreatDetected`);

    // Trim collection to 200 entries (non-blocking)
    trimAlerts().catch(err => console.error('[Cleanup] ❌', err.message));

    return res.status(201).json({
      success: true,
      message: 'Alert logged',
      id:      newAlert._id
    });

  } catch (error) {
    console.error(`[Alert]  ❌ Failed to save: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
// INTERNAL ENDPOINT — LIVE TRAFFIC STATS FROM SENSOR
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/internal/stats
 * 
 * Receives live traffic statistics every 2 seconds from sensor.
 * Emits to dashboard for live traffic graph visualization.
 * 
 * Request Body:
 *   window_number (number): Sequential window counter
 *   total_packets (number): Packet count in this window
 *   total_flows (number): Number of unique IP flows
 *   timestamp (string): ISO timestamp
 *   mode (string): "real" or "simulate"
 * 
 * Response:
 *   200: Stats received
 *   401: Invalid secret key
 */
router.post('/internal/stats', (req, res) => {
  
  // Verify sensor authentication
  const secret = req.headers['x-sensor-secret'];
  
  if (secret !== process.env.SENSOR_SECRET) {
    return res.status(401).json({ success: false });
  }

  const { window_number, total_packets, total_flows, timestamp, mode } = req.body;

  // Broadcast to dashboards
  const io = req.app.get('io');
  io.emit('LiveStats', {
    window_number,
    total_packets,
    total_flows,
    timestamp,
    mode
  });

  return res.status(200).json({ success: true });
});


// ══════════════════════════════════════════════════════════════════════════════
// PUBLIC ENDPOINT — FETCH ALERT HISTORY
// ══════════════════════════════════════════════════════════════════════════════

/**
 * GET /api/alerts
 * 
 * Returns last 50 alerts for React dashboard initial load.
 * Excludes 'features' field to reduce payload size.
 * 
 * Response:
 *   200: Array of alerts (newest first)
 *   500: Database error
 */
router.get('/alerts', async (req, res) => {
  try {
    const alerts = await Alert
      .find()
      .sort({ createdAt: -1 })
      .limit(50)
      .select('-features');

    console.log(`[Alerts] 📋 Fetched ${alerts.length} alerts`);

    return res.status(200).json({
      success: true,
      count:   alerts.length,
      data:    alerts
    });

  } catch (error) {
    console.error(`[Alerts] ❌ Fetch failed: ${error.message}`);
    return res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
// DEMO ENDPOINT — TRIGGER FAKE ATTACK
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/test/trigger-attack
 * 
 * Creates a fake high-confidence (99.8%) alert for demo purposes.
 * Triggered by "Launch Attack" button on dashboard.
 * 
 * Response:
 *   200: Simulated attack created
 *   500: Database error
 */
router.post('/test/trigger-attack', async (req, res) => {

  console.log('[Demo]  💥 Received request to trigger simulated attack');

  try {
    const fakeAlert = {
      source_ip:   '192.0.2.1',
      probability: 99.8,
      threat_type: 'DDoS',
      features:    { "Flow Packets/s": 15000, "Flow IAT Mean": 100 },
      sensor_timestamp: new Date().toISOString()
    };

    const newAlert = await Alert.create(fakeAlert);
    console.log(`[Demo]  ✅ Simulated alert saved to MongoDB | ID: ${newAlert._id}`);

    const io = req.app.get('io');
    io.emit('ThreatDetected', {
      _id:         newAlert._id,
      source_ip:   newAlert.source_ip,
      probability: newAlert.probability,
      threat_type: newAlert.threat_type,
      createdAt:   newAlert.createdAt
    });
    console.log(`[Demo]  📡 Socket.io event emitted → ThreatDetected`);

    // Trim collection to 200 entries (non-blocking)
    trimAlerts().catch(err => console.error('[Cleanup] ❌', err.message));

    return res.status(200).json({ success: true, message: 'Attack triggered' });

  } catch (error) {
    console.error(`[Demo]  ❌ Failed to trigger attack: ${error.message}`);
    return res.status(500).json({ success: false, message: 'Internal server error' });
  }
});


// ══════════════════════════════════════════════════════════════════════════════
// MANUAL PREDICTION ENDPOINT — USER-SUBMITTED FEATURES
// ══════════════════════════════════════════════════════════════════════════════

/**
 * POST /api/predict/manual
 * 
 * Receives 15 network features from dashboard manual input form.
 * Spawns Python script (predict_manual.py) to run real XGBoost prediction.
 * If MALICIOUS (>80%), saves to MongoDB and emits Socket.io event.
 * 
 * Request Body:
 *   features (object): 15 network flow features
 * 
 * Response:
 *   200: Prediction result
 *   400: Missing features
 *   500: Python error or parse error
 */
router.post('/predict/manual', async (req, res) => {
  console.log('[Manual] Received prediction request');

  const { features } = req.body;

  if (!features) {
    return res.status(400).json({
      success: false,
      message: 'Features object is required'
    });
  }

  // Path to Python prediction script
  // In Docker: /app/sensor/predict_manual.py (copied by Dockerfile.backend)
  // In local dev: ../../sensor/predict_manual.py relative to routes/
  const pythonScript = path.join(__dirname, '..', '..', 'sensor', 'predict_manual.py');

  // Python executable:
  //   - Docker: 'python3' (set via PYTHON_PATH env var in docker-compose)
  //   - Local Windows dev: .venv/Scripts/python.exe
  const pythonPath = process.env.PYTHON_PATH ||
    path.join(__dirname, '..', '..', '.venv', 'Scripts', 'python.exe');

  // Spawn Python process
  const python = spawn(pythonPath, [pythonScript]);

  let result = '';
  let error = '';

  // Send features to Python via stdin
  python.stdin.write(JSON.stringify(features));
  python.stdin.end();

  // Collect stdout (prediction result)
  python.stdout.on('data', (data) => {
    result += data.toString();
  });

  // Collect stderr (errors)
  python.stderr.on('data', (data) => {
    error += data.toString();
  });

  // Handle process completion
  python.on('close', async (code) => {
    console.log(`[Manual] Python process exited with code ${code}`);

    if (code !== 0) {
      console.error('[Manual] Python error:', error);
      return res.status(500).json({
        success: false,
        message: 'ML prediction failed',
        error: error
      });
    }

    try {
      const prediction = JSON.parse(result.trim());
      console.log('[Manual] Prediction result:', prediction);

      // If threat detected, save to MongoDB
      if (prediction.is_threat) {
        console.log('[Manual] 🚨 Threat detected! Saving to database...');

        const newAlert = await Alert.create({
          source_ip:        'MANUAL-INPUT',
          probability:      prediction.probability,
          threat_type:      'Manual-Test',
          features:         features,
          sensor_timestamp: new Date().toISOString()
        });

        console.log(`[Manual] ✅ Saved to MongoDB | ID: ${newAlert._id}`);

        // Broadcast to dashboards
        const io = req.app.get('io');
        io.emit('ThreatDetected', {
          _id:         newAlert._id,
          source_ip:   newAlert.source_ip,
          probability: newAlert.probability,
          threat_type: newAlert.threat_type,
          createdAt:   newAlert.createdAt
        });

        console.log('[Manual] 📡 Socket.io event emitted → ThreatDetected');

        // Trim collection to 200 entries (non-blocking)
        trimAlerts().catch(err => console.error('[Cleanup] ❌', err.message));
      }

      return res.status(200).json({
        success: true,
        prediction: prediction.prediction,
        probability: prediction.probability,
        label: prediction.label,
        saved: prediction.is_threat
      });

    } catch (parseError) {
      console.error('[Manual] Failed to parse Python output:', result);
      return res.status(500).json({
        success: false,
        message: 'Failed to parse prediction result',
        raw: result
      });
    }
  });

  // Handle spawn errors
  python.on('error', (err) => {
    console.error('[Manual] Failed to spawn Python:', err);
    return res.status(500).json({
      success: false,
      message: 'Failed to start Python process',
      error: err.message
    });
  });
});


module.exports = router;