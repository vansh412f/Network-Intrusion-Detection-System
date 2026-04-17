// ============================================================
// src/components/ManualInputModal.jsx
// Professional 15-feature input with validation and constraints
// ============================================================

import { useState } from 'react'

// Feature definitions with constraints
const FEATURE_CONFIG = {
  "Flow Duration": { 
    min: 0, 
    max: 120000000, 
    step: 1000,
    placeholder: "0 - 120,000,000 μs"
  },
  "Flow IAT Mean": { 
    min: 0, 
    max: 10000000, 
    step: 1,
    placeholder: "0 - 10,000,000 μs"
  },
  "Flow IAT Max": { 
    min: 0, 
    max: 50000000, 
    step: 1,
    placeholder: "0 - 50,000,000 μs"
  },
  "Flow IAT Std": { 
    min: 0, 
    max: 10000000, 
    step: 0.1,
    placeholder: "0 - 10,000,000"
  },
  "Fwd Packets/s": { 
    min: 0, 
    max: 1000000, 
    step: 1,
    placeholder: "0 - 1,000,000"
  },
  "Bwd Packets/s": { 
    min: 0, 
    max: 1000000, 
    step: 1,
    placeholder: "0 - 1,000,000"
  },
  "Flow Packets/s": { 
    min: 0, 
    max: 2000000, 
    step: 1,
    placeholder: "0 - 2,000,000"
  },
  "Flow Bytes/s": { 
    min: 0, 
    max: 100000000, 
    step: 1,
    placeholder: "0 - 100,000,000"
  },
  "Fwd Packet Length Max": { 
    min: 0, 
    max: 65535, 
    step: 1,
    placeholder: "0 - 65,535 bytes"
  },
  "Fwd Packet Length Min": { 
    min: 0, 
    max: 65535, 
    step: 1,
    placeholder: "0 - 65,535 bytes"
  },
  "Fwd Packets Length Total": { 
    min: 0, 
    max: 100000000, 
    step: 1,
    placeholder: "0 - 100,000,000 bytes"
  },
  "Packet Length Max": { 
    min: 0, 
    max: 65535, 
    step: 1,
    placeholder: "0 - 65,535 bytes"
  },
  "Fwd Act Data Packets": { 
    min: 0, 
    max: 32767, 
    step: 1,
    placeholder: "0 - 32,767"
  },
  "Total Backward Packets": { 
    min: 0, 
    max: 32767, 
    step: 1,
    placeholder: "0 - 32,767"
  },
}

const FEATURE_KEYS = Object.keys(FEATURE_CONFIG)

const DDOS_TEMPLATE = {
  "Flow Duration": 1000000,
  "Flow IAT Mean": 30,
  "Flow IAT Max": 300,
  "Flow IAT Std": 10,
  "Fwd Packets/s": 8000,
  "Bwd Packets/s": 8000,
  "Flow Packets/s": 16000,
  "Flow Bytes/s": 30000,
  "Fwd Packet Length Max": 0,
  "Fwd Packet Length Min": 0,
  "Fwd Packets Length Total": 0,
  "Packet Length Max": 0,
  "Fwd Act Data Packets": 0,
  "Total Backward Packets": 8000,
  "ACK Flag Count": '0'
}

const BENIGN_TEMPLATE = {
  "Flow Duration": 500000,
  "Flow IAT Mean": 50000,
  "Flow IAT Max": 200000,
  "Flow IAT Std": 25000,
  "Fwd Packets/s": 50,
  "Bwd Packets/s": 40,
  "Flow Packets/s": 90,
  "Flow Bytes/s": 5000,
  "Fwd Packet Length Max": 1400,
  "Fwd Packet Length Min": 40,
  "Fwd Packets Length Total": 8000,
  "Packet Length Max": 1400,
  "Fwd Act Data Packets": 10,
  "Total Backward Packets": 15,
  "ACK Flag Count": '1'
}

export function ManualInputModal({ isOpen, onClose, onSubmit }) {
  const [features, setFeatures] = useState(DDOS_TEMPLATE)
  const [loading, setLoading] = useState(false)
  const [errors, setErrors] = useState({})
  const [warnings, setWarnings] = useState({})

  if (!isOpen) return null

  // Validate and set value
  const handleChange = (key, rawValue) => {
    const config = FEATURE_CONFIG[key]
    let value = parseFloat(rawValue)
    
    // Handle empty or NaN
    if (rawValue === '' || isNaN(value)) {
      setFeatures(prev => ({ ...prev, [key]: 0 }))
      setErrors(prev => ({ ...prev, [key]: null }))
      setWarnings(prev => ({ ...prev, [key]: null }))
      return
    }

    // Check for negative
    if (value < 0) {
      value = 0
      setErrors(prev => ({ ...prev, [key]: 'Cannot be negative' }))
    } else {
      setErrors(prev => ({ ...prev, [key]: null }))
    }

    // Check for extreme values (warning only)
    if (value > config.max) {
      setWarnings(prev => ({ ...prev, [key]: `Unusually high (max: ${config.max.toLocaleString()})` }))
    } else {
      setWarnings(prev => ({ ...prev, [key]: null }))
    }

    setFeatures(prev => ({ ...prev, [key]: value }))
  }

  // Validate before submit
  const validateAll = () => {
    let hasErrors = false
    const newErrors = {}

    FEATURE_KEYS.forEach(key => {
      const value = features[key]
      if (value < 0) {
        newErrors[key] = 'Cannot be negative'
        hasErrors = true
      }
      if (typeof value !== 'number' || isNaN(value)) {
        newErrors[key] = 'Invalid number'
        hasErrors = true
      }
    })

    setErrors(newErrors)
    return !hasErrors
  }

  const handleSubmit = async () => {
    if (!validateAll()) {
      alert('Please fix the errors before submitting.')
      return
    }

    setLoading(true)
    try {
      await onSubmit(features)
      setLoading(false)
      onClose()
    } catch (error) {
      setLoading(false)
      alert('Prediction failed. Check console for details.')
    }
  }

  const handleReset = () => {
    setFeatures(DDOS_TEMPLATE)
    setErrors({})
    setWarnings({})
  }

  // Count warnings
  const warningCount = Object.values(warnings).filter(Boolean).length

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 bg-black/70 z-40" onClick={onClose} />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div className="bg-slate-800 rounded-xl border border-slate-700 w-full max-w-2xl max-h-[90vh] flex flex-col">
          
          {/* Header */}
          <div className="border-b border-slate-700 px-5 py-3 flex items-center justify-between flex-shrink-0">
            <div>
              <h2 className="text-lg font-bold text-white">Manual Feature Input</h2>
              <p className="text-xs text-slate-400">
                Enter 15 network flow features for ML prediction
              </p>
            </div>
            <button 
              onClick={onClose} 
              className="text-slate-400 hover:text-white text-xl p-1"
            >
              ✕
            </button>
          </div>

          {/* Warning Banner */}
          {warningCount > 0 && (
            <div className="bg-yellow-500/10 border-b border-yellow-500/30 px-5 py-2 flex-shrink-0">
              <p className="text-yellow-400 text-xs">
                ⚠️ {warningCount} field(s) have unusually high values. Prediction will still run.
              </p>
            </div>
          )}

          {/* Form — 2 Columns */}
          <div className="p-4 overflow-y-auto flex-1">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3">
              {FEATURE_KEYS.map((key) => {
                const config = FEATURE_CONFIG[key]
                const hasError = errors[key]
                const hasWarning = warnings[key]
                
                return (
                  <div key={key}>
                    <label className="block text-xs text-slate-400 mb-1 truncate" title={key}>
                      {key}
                    </label>
                    <input
                      type="number"
                      step={config.step}
                      min={config.min}
                      value={features[key]}
                      onChange={(e) => handleChange(key, e.target.value)}
                      placeholder={config.placeholder}
                      className={`w-full bg-slate-900 border rounded
                                 px-2 py-1.5 text-sm text-white
                                 focus:outline-none transition-colors
                                 ${hasError 
                                   ? 'border-red-500 focus:border-red-400' 
                                   : hasWarning 
                                     ? 'border-yellow-500 focus:border-yellow-400'
                                     : 'border-slate-700 focus:border-blue-500'
                                 }`}
                    />
                    {hasError && (
                      <p className="text-red-400 text-[10px] mt-0.5">{hasError}</p>
                    )}
                    {hasWarning && !hasError && (
                      <p className="text-yellow-400 text-[10px] mt-0.5">{hasWarning}</p>
                    )}
                  </div>
                )
              })}
            </div>

            {/* ACK Flag */}
            <div className="mt-4 flex items-center justify-center gap-6 pt-3 border-t border-slate-700">
              <span className="text-sm text-slate-400">ACK Flag Count</span>
              <label className="flex items-center gap-1.5 text-sm text-slate-300 cursor-pointer">
                <input
                  type="radio"
                  name="ack"
                  value="0"
                  checked={features["ACK Flag Count"] === '0'}
                  onChange={(e) => setFeatures(prev => ({ ...prev, "ACK Flag Count": e.target.value }))}
                  className="w-3.5 h-3.5 accent-blue-500"
                />
                0
              </label>
              <label className="flex items-center gap-1.5 text-sm text-slate-300 cursor-pointer">
                <input
                  type="radio"
                  name="ack"
                  value="1"
                  checked={features["ACK Flag Count"] === '1'}
                  onChange={(e) => setFeatures(prev => ({ ...prev, "ACK Flag Count": e.target.value }))}
                  className="w-3.5 h-3.5 accent-blue-500"
                />
                1
              </label>
            </div>
          </div>

          {/* Footer */}
          <div className="border-t border-slate-700 px-5 py-3 flex items-center justify-between flex-shrink-0">
            <div className="flex gap-2">
              <button
                onClick={() => {
                  setFeatures(DDOS_TEMPLATE)
                  setErrors({})
                  setWarnings({})
                }}
                className="px-3 py-1.5 bg-red-600/20 hover:bg-red-600/30 
                           text-red-400 text-xs rounded-lg transition-colors"
              >
                🚨 DDoS
              </button>
              <button
                onClick={() => {
                  setFeatures(BENIGN_TEMPLATE)
                  setErrors({})
                  setWarnings({})
                }}
                className="px-3 py-1.5 bg-green-600/20 hover:bg-green-600/30 
                           text-green-400 text-xs rounded-lg transition-colors"
              >
                ✅ Benign
              </button>
              <button
                onClick={handleReset}
                className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 
                           text-slate-300 text-xs rounded-lg transition-colors"
              >
                ↺ Reset
              </button>
            </div>
            <div className="flex gap-2">
              <button
                onClick={onClose}
                className="px-4 py-1.5 bg-slate-700 hover:bg-slate-600 
                           text-white text-sm rounded-lg transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleSubmit}
                disabled={loading || Object.values(errors).some(Boolean)}
                className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 
                           text-white text-sm rounded-lg transition-colors
                           disabled:opacity-50 disabled:cursor-not-allowed
                           flex items-center gap-2"
              >
                {loading ? (
                  <>
                    <span className="animate-spin">⏳</span>
                    Running...
                  </>
                ) : (
                  <>
                    🚀 Run Prediction
                  </>
                )}
              </button>
            </div>
          </div>

        </div>
      </div>
    </>
  )
}