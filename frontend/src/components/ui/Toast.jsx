const TOAST_STYLES = {
  success: {
    icon: '✓',
    label: 'Success',
    container: 'border-emerald-500/30 bg-[#0f1f25] shadow-[0_16px_50px_rgba(16,185,129,0.12)]',
    iconContainer: 'bg-emerald-500/15 text-emerald-400',
    accent: 'bg-emerald-400'
  },
  error: {
    icon: '!',
    label: 'Error',
    container: 'border-red-500/30 bg-[#21151f] shadow-[0_16px_50px_rgba(239,68,68,0.14)]',
    iconContainer: 'bg-red-500/15 text-red-400',
    accent: 'bg-red-400'
  },
  warning: {
    icon: '!',
    label: 'Warning',
    container: 'border-amber-500/30 bg-[#211d18] shadow-[0_16px_50px_rgba(245,158,11,0.12)]',
    iconContainer: 'bg-amber-500/15 text-amber-400',
    accent: 'bg-amber-400'
  },
  info: {
    icon: 'i',
    label: 'Information',
    container: 'border-blue-500/30 bg-[#101b2d] shadow-[0_16px_50px_rgba(59,130,246,0.14)]',
    iconContainer: 'bg-blue-500/15 text-blue-400',
    accent: 'bg-blue-400'
  },
  blocked: {
    icon: '⛔',
    label: 'Blocked',
    container: 'border-red-500/30 bg-[#21151f] shadow-[0_16px_50px_rgba(239,68,68,0.14)]',
    iconContainer: 'bg-red-500/15 text-red-400',
    accent: 'bg-red-400'
  }
}

export function Toast({ toasts, onRemove }) {
  if (!toasts.length) return null

  return (
    <div
      className="pointer-events-none fixed inset-x-3 bottom-3 z-[100] flex flex-col items-end gap-3 sm:inset-x-auto sm:right-5 sm:bottom-5 sm:w-full sm:max-w-sm"
      aria-live="polite"
      aria-atomic="false"
    >
      {toasts.map((toast) => {
        const style = TOAST_STYLES[toast.type] || TOAST_STYLES.info
        const isUrgent = toast.type === 'error' || toast.type === 'warning' || toast.type === 'blocked'

        return (
          <div
            key={toast.id}
            role={isUrgent ? 'alert' : 'status'}
            className={`pointer-events-auto relative w-full overflow-hidden rounded-xl border backdrop-blur-xl transition-all duration-300 starting:translate-x-8 starting:opacity-0 ${style.container}`}
          >
            <div className={`absolute inset-y-0 left-0 w-1 ${style.accent}`} />

            <div className="flex items-start gap-3 px-4 py-3.5 pl-5">
              <div
                className={`mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-sm font-bold ${style.iconContainer}`}
                aria-hidden="true"
              >
                {style.icon}
              </div>

              <div className="min-w-0 flex-1">
                <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[var(--color-text-secondary)]">
                  {toast.title || style.label}
                </p>
                <p className="mt-1 break-words text-sm leading-5 text-[var(--color-text-primary)]">
                  {toast.message}
                </p>
              </div>

              <button
                type="button"
                onClick={() => onRemove(toast.id)}
                className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-[var(--color-text-muted)] transition-colors hover:bg-white/5 hover:text-[var(--color-text-primary)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[var(--color-primary-blue)]"
                aria-label={`Dismiss ${style.label.toLowerCase()} notification`}
              >
                <svg
                  className="h-4 w-4"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  aria-hidden="true"
                >
                  <path strokeLinecap="round" d="M6 6l12 12M18 6 6 18" />
                </svg>
              </button>
            </div>
          </div>
        )
      })}
    </div>
  )
}