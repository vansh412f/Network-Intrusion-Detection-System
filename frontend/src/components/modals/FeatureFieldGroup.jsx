export function FeatureFieldGroup({ label, icon: GroupIcon, fields, features, errors, warnings, handleChange }) {
  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        <GroupIcon
          size={12}
          strokeWidth={1.75}
          style={{ color: 'var(--color-text-muted)' }}
          aria-hidden="true"
        />
        <span
          className="font-semibold uppercase"
          style={{
            fontSize:      '10px',
            letterSpacing: '0.1em',
            color:         'var(--color-text-muted)'
          }}
        >
          {label}
        </span>
        <div
          className="flex-1 border-t"
          style={{ borderColor: 'var(--color-border-card)' }}
        />
      </div>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2.5">
        {fields.map(({ key, min, max, step, placeholder }) => {
          const hasError   = errors[key]
          const hasWarning = warnings[key]
          return (
            <div key={key}>
              <label
                className="mb-1 block truncate font-medium"
                style={{
                  fontSize: '11px',
                  color:    'var(--color-text-secondary)'
                }}
                title={key}
              >
                {key}
                {placeholder && (
                  <span style={{ color: 'var(--color-text-muted)', marginLeft: '4px' }}>
                    ({placeholder})
                  </span>
                )}
              </label>
              <input
                type="number"
                step={step}
                min={min}
                value={features[key] ?? 0}
                onChange={e => handleChange(key, e.target.value)}
                className="w-full rounded-lg border px-3 py-1.5 text-sm outline-none transition-colors duration-150"
                style={{
                  backgroundColor: 'var(--color-bg-page)',
                  borderColor:     hasError   ? '#ef4444' :
                                   hasWarning ? '#f59e0b' :
                                                'var(--color-border-card)',
                  color:           'var(--color-text-primary)'
                }}
                onFocus={e => {
                  if (!hasError && !hasWarning) {
                    e.currentTarget.style.borderColor = 'var(--color-primary-blue)'
                  }
                }}
                onBlur={e => {
                  if (!hasError && !hasWarning) {
                    e.currentTarget.style.borderColor = 'var(--color-border-card)'
                  }
                }}
              />
              {hasError && (
                <p style={{ fontSize: '10px', color: '#ef4444', marginTop: '2px' }}>
                  {hasError}
                </p>
              )}
              {hasWarning && !hasError && (
                <p style={{ fontSize: '10px', color: '#f59e0b', marginTop: '2px' }}>
                  {hasWarning}
                </p>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
