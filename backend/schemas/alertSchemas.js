const { z } = require('zod')

const internalAlertSchema = z.object({
  source_ip: z.string().trim().min(1),
  probability: z.number().min(0).max(100),
  timestamp: z.string().optional(),
  threat_type: z.enum(['DDoS', 'Manual-Test']).optional(),
  features: z.record(z.string(), z.any()).optional()
})

const manualPredictSchema = z.object({
  features: z.object({
    'Flow Duration':            z.number(),
    'Flow IAT Mean':            z.number(),
    'Flow IAT Max':             z.number(),
    'Flow IAT Std':             z.number(),
    'Fwd Packets/s':            z.number(),
    'Bwd Packets/s':            z.number(),
    'Flow Packets/s':           z.number(),
    'Flow Bytes/s':             z.number(),
    'Fwd Packet Length Max':    z.number(),
    'Fwd Packet Length Min':    z.number(),
    'Fwd Packets Length Total': z.number(),
    'Packet Length Max':        z.number(),
    'Fwd Act Data Packets':     z.number(),
    'Total Backward Packets':   z.number(),
    'ACK Flag Count':           z.enum(['0', '1'])
  })
})

const statsSchema = z.object({
  window_number: z.number().int().nonnegative(),
  total_packets: z.number().int().nonnegative(),
  total_flows:   z.number().int().nonnegative(),
  timestamp:     z.string().optional(),
  mode:          z.string().optional()
})

const registerSchema = z.object({
  name:        z.string().min(2).max(50),
  email:       z.string().email(),
  password:    z.string().min(8)
})

const loginSchema = z.object({
  email:    z.string().email(),
  password: z.string().min(1)
})

const updateProfileSchema = z.object({
  name:                   z.string().min(2).max(50).optional(),
  email_notifications:    z.boolean().optional(),
  min_severity_for_email: z.enum(['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']).optional()
})

const blockIPSchema = z.object({
  ip:     z.string().ip(),
  reason: z.string().max(200).optional()
})

const unblockIPSchema = z.object({
  ip: z.string().ip()
})

module.exports = {
  internalAlertSchema,
  manualPredictSchema,
  statsSchema,
  registerSchema,
  loginSchema,
  updateProfileSchema,
  blockIPSchema,
  unblockIPSchema
}