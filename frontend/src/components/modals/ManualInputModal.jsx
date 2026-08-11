import { useState, useCallback, useEffect } from 'react'
import { Zap, Activity, RotateCcw, X } from 'lucide-react'
import { FeatureFieldGroup } from './FeatureFieldGroup'
import { FEATURE_GROUPS, ALL_FIELDS, TEMPLATES } from './ManualInputData'

// ── COMPONENT ────────────────────────────────────────────────────────────────

export function ManualInputModal({ isOpen, onClose, onSubmit }) {
  const [features, setFeatures] = useState(TEMPLATES.NORMAL.features)
  const [errors,   setErrors]   = useState({})
  const [warnings, setWarnings] = useState({})
  const [loading,  setLoading]  = useState(false)

  // Reset state every time modal opens (but preserve if currently predicting)
  useEffect(() => {
    if (!isOpen) return
    setLoading(prevLoading => {
      if (!prevLoading) {
        setFeatures(TEMPLATES.NORMAL.features)
        setErrors({})
        setWarnings({})
      }
      return prevLoading
    })
  }, [isOpen])

  // Escape key handler
  useEffect(() => {
    if (!isOpen || loading) return
    const handleKeyDown = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose, loading])

  const handleChange = useCallback((key, raw) => {
    const config = ALL_FIELDS.find(f => f.key === key)
    const value  = parseFloat(raw)

    if (raw === '' || isNaN(value)) {
      setFeatures(prev  => ({ ...prev,  [key]: 0 }))
      setErrors(prev    => ({ ...prev,  [key]: null }))
      setWarnings(prev  => ({ ...prev,  [key]: null }))
      return
    }

    const clamped = value < 0 ? 0 : value

    setErrors(prev => ({
      ...prev,
      [key]: value < 0 ? 'Cannot be negative' : null
    }))

    setWarnings(prev => ({
      ...prev,
      [key]: config && clamped > config.max
        ? `High (max: ${config.max.toLocaleString()})`
        : null
    }))

    setFeatures(prev => ({ ...prev, [key]: clamped }))
  }, [])

  const loadTemplate = useCallback((key) => {
    setFeatures(TEMPLATES[key].features)
    setErrors({})
    setWarnings({})
  }, [])

  const handleSubmit = useCallback(async () => {
    setLoading(true)
    try {
      await onSubmit(features)
      // Result displayed via toast in parent — no local result state
    } catch {
      // Error handled by parent via toast
    } finally {
      setLoading(false)
    }
  }, [features, onSubmit])

  if (!isOpen) return null

  const warningCount  = Object.values(warnings).filter(Boolean).length
  const hasErrors     = Object.values(errors).some(Boolean)

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 z-40 backdrop-blur-sm"
        style={{ backgroundColor: 'rgba(0,0,0,0.7)', cursor: loading ? 'not-allowed' : 'pointer' }}
        onClick={() => !loading && onClose()}
      />

      {/* Modal */}
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        <div
          className="relative flex w-full max-w-2xl flex-col rounded-xl border animate-fade-slide"
          style={{
            backgroundColor: 'var(--color-bg-elevated)',
            borderColor:     'var(--color-border-card)',
            boxShadow:       '0 20px 60px rgba(0,0,0,0.55)',
            maxHeight:       '90vh'
          }}
        >
          {/* Header */}
          <div
            className="flex flex-shrink-0 items-center justify-between border-b px-5 py-3.5"
            style={{ borderColor: 'var(--color-border-card)' }}
          >
            <div>
              <h2 className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>
                Manual Feature Input
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                15 network flow features · XGBoost ML prediction
              </p>
            </div>
            <button
              onClick={() => !loading && onClose()}
              disabled={loading}
              className="rounded-lg p-1.5 transition-colors duration-150 disabled:opacity-50 disabled:cursor-not-allowed"
              style={{ color: 'var(--color-text-muted)' }}
              onMouseEnter={e => e.currentTarget.style.color = 'var(--color-text-primary)'}
              onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-muted)'}
              aria-label="Close modal"
            >
              <X size={15} strokeWidth={2} />
            </button>
          </div>

          {/* Warning banner — only shown when fields exceed documented max */}
          {warningCount > 0 && (
            <div
              className="flex flex-shrink-0 items-center gap-2 border-b px-5 py-2"
              style={{
                borderColor:     'rgba(245,158,11,0.2)',
                backgroundColor: 'rgba(245,158,11,0.06)'
              }}
            >
              <Activity size={12} strokeWidth={2} style={{ color: '#f59e0b' }} aria-hidden="true" />
              <p style={{ fontSize: '11px', color: '#f59e0b' }}>
                {warningCount} field{warningCount > 1 ? 's' : ''} have unusually high values — prediction will still run
              </p>
            </div>
          )}

          {/* Scrollable feature fields */}
          <div className="flex-1 overflow-y-auto px-5 py-4 space-y-5">
            {FEATURE_GROUPS.map(({ label, icon: GroupIcon, fields }) => (
              <FeatureFieldGroup
                key={label}
                label={label}
                icon={GroupIcon}
                fields={fields}
                features={features}
                errors={errors}
                warnings={warnings}
                handleChange={handleChange}
              />
            ))}

            {/* ACK Flag */}
            <div
              className="flex items-center justify-center gap-6 border-t pt-4"
              style={{ borderColor: 'var(--color-border-card)' }}
            >
              <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
                ACK Flag Count
              </span>
              {['0', '1'].map(val => (
                <label
                  key={val}
                  className="flex cursor-pointer items-center gap-1.5"
                  style={{ fontSize: '13px', color: 'var(--color-text-secondary)' }}
                >
                  <input
                    type="radio"
                    name="ack"
                    value={val}
                    checked={features['ACK Flag Count'] === val}
                    onChange={() => setFeatures(prev => ({ ...prev, 'ACK Flag Count': val }))}
                    className="h-3.5 w-3.5"
                    style={{ accentColor: 'var(--color-primary-blue)' }}
                  />
                  {val}
                </label>
              ))}
            </div>
          </div>

          {/* Footer */}
          <div
            className="flex flex-shrink-0 flex-wrap items-center justify-between gap-3 border-t px-5 py-3.5"
            style={{ borderColor: 'var(--color-border-card)' }}
          >
            {/* Template buttons */}
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(TEMPLATES).map(([key, tmpl]) => (
                <button
                  key={key}
                  onClick={() => loadTemplate(key)}
                  className="rounded-lg px-3 py-1.5 text-xs font-medium transition-opacity duration-150"
                  style={{
                    backgroundColor: tmpl.bg,
                    border:          `1px solid ${tmpl.border}`,
                    color:           tmpl.color
                  }}
                  onMouseEnter={e => e.currentTarget.style.opacity = '0.75'}
                  onMouseLeave={e => e.currentTarget.style.opacity = '1'}
                >
                  {tmpl.label}
                </button>
              ))}

              {/* Reset button */}
              <button
                onClick={() => loadTemplate('NORMAL')}
                className="flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors duration-150"
                style={{
                  borderColor:     'var(--color-border-card)',
                  backgroundColor: 'transparent',
                  color:           'var(--color-text-muted)'
                }}
                onMouseEnter={e => e.currentTarget.style.color = 'var(--color-text-secondary)'}
                onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-muted)'}
              >
                <RotateCcw size={11} strokeWidth={2} aria-hidden="true" />
                Reset
              </button>
            </div>

            {/* Run Prediction */}
            <button
              onClick={handleSubmit}
              disabled={loading || hasErrors}
              className="flex items-center gap-2 rounded-lg px-5 py-2 text-sm font-semibold text-white transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50"
              style={{ backgroundColor: 'var(--color-primary-blue)' }}
              onMouseEnter={e => { if (!loading && !hasErrors) e.currentTarget.style.backgroundColor = 'var(--color-primary-hover)' }}
              onMouseLeave={e => { e.currentTarget.style.backgroundColor = 'var(--color-primary-blue)' }}
            >
              {loading ? (
                <>
                  <span
                    className="h-4 w-4 rounded-full border-2 animate-spin"
                    style={{ borderColor: 'rgba(255,255,255,0.3)', borderTopColor: 'white' }}
                  />
                  Running...
                </>
              ) : (
                <>
                  <Zap size={13} strokeWidth={2} aria-hidden="true" />
                  Run Prediction
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </>
  )
}