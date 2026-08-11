const mongoose = require('mongoose')

const BlocklistSchema = new mongoose.Schema(
  {
    ip: {
      type:     String,
      required: true,
      unique:   true,
      trim:     true
    },
    blockedBy: {
      type:     String,
      required: true
    },
    reason: {
      type:      String,
      maxlength: 200,
      default:   ''
    }
  },
  { timestamps: { createdAt: true, updatedAt: false } }
)

// Auto-delete blocks after 30 minutes
BlocklistSchema.index({ createdAt: 1 }, { expireAfterSeconds: 1800 })

module.exports = mongoose.model('Blocklist', BlocklistSchema)