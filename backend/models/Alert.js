const mongoose = require('mongoose')

const AlertSchema = new mongoose.Schema(
  {
    source_ip: {
      type:     String,
      required: true,
      trim:     true
    },
    probability: {
      type:     Number,
      required: true,
      min:      0,
      max:      100
    },
    threat_type: {
      type:    String,
      default: 'DDoS',
      enum:    ['DDoS', 'Manual-Test']
    },
    features: {
      type:    mongoose.Schema.Types.Mixed,
      default: {}
    },
    severity: {
      type:     String,
      required: true,
      enum:     ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    },
    blocked: {
      type:    Boolean,
      default: false
    },
    sensor_timestamp: {
      type: Date
    }
  },
  {
    timestamps: true
  }
)

AlertSchema.index({ source_ip: 1 })
AlertSchema.index({ createdAt: -1 })

// Safety net — MongoDB auto-deletes alerts older than 30 days
AlertSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 2592000 }
)

module.exports = mongoose.model('Alert', AlertSchema)