import { motion } from 'framer-motion'
import { ChevronRight } from 'lucide-react'

export function DocsSidebar({ sections, activeId, scrollTo }) {
  return (
    <aside className="hidden w-52 flex-shrink-0 lg:block">
      <div className="sticky top-24">
        <p
          className="mb-3 px-3 font-semibold uppercase"
          style={{ fontSize: '11px', letterSpacing: '0.1em', color: 'var(--color-text-muted)' }}
        >
          Contents
        </p>

        <nav className="relative space-y-0.5">
          {sections.map(({ id, label, icon: Icon }) => {
            const isActive = activeId === id
            return (
              <button
                key={id}
                onClick={() => scrollTo(id)}
                className="relative flex w-full items-center gap-2 overflow-hidden rounded-lg px-3 py-2 text-left text-sm transition-colors duration-150"
                style={{
                  color: isActive
                    ? 'var(--color-primary-blue)'
                    : 'var(--color-text-secondary)'
                }}
                onMouseEnter={e => {
                  if (!isActive) e.currentTarget.style.color = 'var(--color-text-primary)'
                }}
                onMouseLeave={e => {
                  if (!isActive) e.currentTarget.style.color = 'var(--color-text-secondary)'
                }}
              >
                {isActive && (
                  <motion.div
                    layoutId="docs-sidebar-bg"
                    className="absolute inset-0 rounded-lg"
                    style={{ backgroundColor: 'rgba(59,130,246,0.08)' }}
                    transition={{ type: 'spring', stiffness: 400, damping: 35 }}
                  />
                )}

                {isActive && (
                  <motion.div
                    layoutId="docs-sidebar-border"
                    className="absolute left-0 top-1 bottom-1 rounded-full"
                    style={{ width: '2px', backgroundColor: 'var(--color-primary-blue)' }}
                    transition={{ type: 'spring', stiffness: 400, damping: 35 }}
                  />
                )}

                <Icon
                  size={13}
                  strokeWidth={1.75}
                  aria-hidden="true"
                  style={{ position: 'relative', zIndex: 1, flexShrink: 0 }}
                />
                <span style={{ position: 'relative', zIndex: 1 }}>
                  {label}
                </span>
                {isActive && (
                  <ChevronRight
                    size={12}
                    strokeWidth={2}
                    className="ml-auto"
                    aria-hidden="true"
                    style={{ position: 'relative', zIndex: 1 }}
                  />
                )}
              </button>
            )
          })}
        </nav>
      </div>
    </aside>
  )
}
