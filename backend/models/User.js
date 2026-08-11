const mongoose = require('mongoose')
const bcrypt   = require('bcryptjs')
const crypto   = require('crypto')

function generateUserId() {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
  let result = 'user_'
  for (let i = 0; i < 6; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length))
  }
  return result
}

const UserSchema = new mongoose.Schema(
  {
    userId: {
      type:     String,
      unique:   true,
      trim:     true,
      lowercase: true
    },
    name: {
      type:      String,
      required:  true,
      trim:      true,
      minlength: 2,
      maxlength: 50
    },
    email: {
      type:      String,
      required:  true,
      unique:    true,
      lowercase: true,
      trim:      true
    },
    password: {
      type:      String,
      required:  true,
      minlength: 8,
      select:    false
    },
    email_notifications: {
      type:    Boolean,
      default: true
    },
    min_severity_for_email: {
      type:    String,
      enum:    ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
      default: 'LOW'
    },
    role: {
      type:    String,
      enum:    ['analyst', 'admin'],
      default: 'analyst'
    },
    verified: {
      type:    Boolean,
      default: false
    }
  },
  { timestamps: true }
)

UserSchema.pre('save', async function (next) {
  if (!this.userId) {
    let id = generateUserId()
    let attempts = 0
    while (await mongoose.model('User').findOne({ userId: id }) && attempts < 5) {
      id = generateUserId()
      attempts++
    }
    this.userId = id
  }

  if (!this.isModified('password')) return next()

  try {
    const salt = await bcrypt.genSalt(12)
    this.password = await bcrypt.hash(this.password, salt)
    next()
  } catch (err) {
    next(err)
  }
})

UserSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password)
}

module.exports = mongoose.model('User', UserSchema)