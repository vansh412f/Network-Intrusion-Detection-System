export function SectionTitle({ icon: Icon, title, subtitle }) {
  return (
    <div className="mb-5 flex items-center gap-3">
      <div
        className="flex h-8 w-8 flex-shrink-0 items-center justify-center rounded-lg border"
        style={{ backgroundColor: 'rgba(59,130,246,0.08)', borderColor: 'rgba(59,130,246,0.15)' }}
      >
        <Icon size={14} strokeWidth={1.75} style={{ color: 'var(--color-primary-blue)' }} aria-hidden="true" />
      </div>
      <div>
        <h2 className="text-base font-bold" style={{ color: 'var(--color-text-primary)' }}>{title}</h2>
        {subtitle && (
          <p style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>{subtitle}</p>
        )}
      </div>
    </div>
  )
}
