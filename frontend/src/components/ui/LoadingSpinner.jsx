export function LoadingSpinner({ size = 'md', label = 'Loading...' }) {
  const sizeClass = size === 'sm' ? 'h-6 w-6 border-2' : size === 'lg' ? 'h-12 w-12 border-4' : 'h-8 w-8 border-2'

  return (
    <div className="flex flex-col items-center justify-center gap-3">
      <div
        className={`${sizeClass} rounded-full border-[var(--color-border-card)] border-t-[var(--color-primary-blue)] animate-spin`}
      />
      {label && (
        <p className="text-sm text-[var(--color-text-secondary)]">{label}</p>
      )}
    </div>
  )
}