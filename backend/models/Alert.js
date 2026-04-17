const mongoose = require('mongoose');

const AlertSchema = new mongoose.Schema(
  {
    // IP address that triggered the alert
    source_ip: {
      type:     String,
      required: true,
      trim:     true
    },

    // ML model confidence score (0-100)
    probability: {
      type:    Number,
      required: true,
      min:     0,
      max:     100
    },

    // Type of attack detected
    threat_type: {
      type:    String,
      default: 'DDoS',
      enum:    ['DDoS', 'Manual-Test']
    },

    // The 15 feature values that triggered the alert
    // Stored as a flexible object
    features: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },

    // Whether an email notification was sent
    email_sent: {
      type:    Boolean,
      default: false
    },

    // ISO timestamp string from the sensor
    sensor_timestamp: {
      type: String
    }
  },
  {
    // Automatically adds createdAt and updatedAt fields
    timestamps: true
  }
);

// Index on source_ip for fast lookups
// e.g., "show me all alerts from this IP"
AlertSchema.index({ source_ip: 1 });

// Index on createdAt for fast time-based queries
// e.g., "show me alerts from the last hour"
AlertSchema.index({ createdAt: -1 });

module.exports = mongoose.model('Alert', AlertSchema);