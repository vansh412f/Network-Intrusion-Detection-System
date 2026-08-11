  import { useState } from 'react'
  import { motion, AnimatePresence } from 'framer-motion'
  import { ArrowRight, ChevronLeft, ChevronRight } from 'lucide-react'

  export function HowItWorks({ items, inView }) {
    const [active, setActive] = useState(0)
    const [dragging, setDragging] = useState(false)

    return (
      <div>
        {/* Desktop: 3 columns */}
        <div className="hidden lg:grid lg:grid-cols-3 lg:gap-6 relative">
          {items.map(({ icon: Icon, title, desc, tags }, i) => (
            <div key={i} className="relative">
              <motion.div
                initial={{ opacity: 0, y: 28 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ duration: 0.55, delay: 0.1 + i * 0.13 }}
                whileHover={{ y: -5 }}
                className="rounded-xl border p-6 h-full"
                style={{
                  borderColor:     'var(--color-border-card)',
                  backgroundColor: 'var(--color-bg-card)'
                }}
              >
                <div className="flex items-center gap-3 mb-3">
                  <div
                    className="flex h-9 w-9 items-center justify-center rounded-xl flex-shrink-0"
                    style={{
                      backgroundColor: 'rgba(59,130,246,0.1)',
                      border:          '1px solid rgba(59,130,246,0.2)'
                    }}
                  >
                    <Icon size={18} strokeWidth={1.75} style={{ color: 'var(--color-primary-blue)' }} />
                  </div>
                  <h3 className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>
                    {title}
                  </h3>
                </div>

                <p style={{ fontSize: '12px', lineHeight: '1.7', color: 'var(--color-text-muted)' }}>
                  {desc}
                </p>

                <div className="mt-4 flex flex-wrap gap-1.5">
                  {tags.map(tag => (
                    <span
                      key={tag}
                      className="rounded-full border px-2.5 py-0.5"
                      style={{
                        fontSize:        '10px',
                        borderColor:     'rgba(59,130,246,0.2)',
                        backgroundColor: 'rgba(59,130,246,0.06)',
                        color:           'var(--color-primary-blue)'
                      }}
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </motion.div>

              {/* Arrow between cards */}
              {i < 2 && (
                <motion.div
                  initial={{ opacity: 0, x: -8 }}
                  animate={inView ? { opacity: 1, x: 0 } : {}}
                  transition={{ duration: 0.4, delay: 0.4 + i * 0.13 }}
                  style={{
                    position:  'absolute',
                    right:     '-22px',
                    top:       '50%',
                    transform: 'translateY(-50%)',
                    zIndex:    10
                  }}
                >
                  <ArrowRight
                    size={16}
                    strokeWidth={1.75}
                    style={{ color: 'var(--color-primary-blue)', opacity: 0.5 }}
                  />
                </motion.div>
              )}
            </div>
          ))}
        </div>

        {/* Mobile: drag carousel */}
        <div className="lg:hidden">
          <div className="overflow-hidden rounded-xl">
            <AnimatePresence mode="wait">
              {items.map(({ icon: Icon, title, desc, tags }, i) =>
                i === active ? (
                  <motion.div
                    key={i}
                    initial={{ opacity: 0, x: 40 }}
                    animate={{ opacity: 1, x: 0  }}
                    exit={{    opacity: 0, x: -40 }}
                    transition={{ duration: 0.25 }}
                    whileHover={{ y: -5 }}
                    drag="x"
                    dragConstraints={{ left: 0, right: 0 }}
                    onDragStart={() => setDragging(true)}
                    onDragEnd={(_, info) => {
                      setDragging(false)
                      if (info.offset.x < -60 && active < 2) setActive(a => a + 1)
                      if (info.offset.x >  60 && active > 0) setActive(a => a - 1)
                    }}
                    className="rounded-xl border p-6"
                    style={{
                      borderColor:     'var(--color-border-card)',
                      backgroundColor: 'var(--color-bg-card)',
                      cursor:          dragging ? 'grabbing' : 'grab'
                    }}
                  >
                    <div className="flex items-center gap-3 mb-3">
                      <div
                        className="flex h-9 w-9 items-center justify-center rounded-xl flex-shrink-0"
                        style={{ backgroundColor: 'rgba(59,130,246,0.1)', border: '1px solid rgba(59,130,246,0.2)' }}
                      >
                        <Icon size={18} strokeWidth={1.75} style={{ color: 'var(--color-primary-blue)' }} />
                      </div>
                      <h3 className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>{title}</h3>
                    </div>
                    <p style={{ fontSize: '12px', lineHeight: '1.7', color: 'var(--color-text-muted)' }}>{desc}</p>
                    <div className="mt-4 flex flex-wrap gap-1.5">
                      {tags.map(tag => (
                        <span
                          key={tag}
                          className="rounded-full border px-2.5 py-0.5"
                          style={{ fontSize: '10px', borderColor: 'rgba(59,130,246,0.2)', backgroundColor: 'rgba(59,130,246,0.06)', color: 'var(--color-primary-blue)' }}
                        >
                          {tag}
                        </span>
                      ))}
                    </div>
                  </motion.div>
                ) : null
              )}
            </AnimatePresence>
          </div>

          {/* Dot pagination + arrows */}
          <div className="mt-4 flex items-center justify-center gap-4">
            <button
              onClick={() => setActive(a => Math.max(0, a - 1))}
              disabled={active === 0}
              className="rounded-full p-1.5 border transition-colors"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)',
                opacity:         active === 0 ? 0.3 : 1
              }}
            >
              <ChevronLeft size={14} style={{ color: 'var(--color-text-secondary)' }} />
            </button>

            <div className="flex items-center gap-2">
              {items.map((_, i) => (
                <button
                  key={i}
                  onClick={() => setActive(i)}
                  style={{
                    width:           i === active ? '20px' : '6px',
                    height:          '6px',
                    borderRadius:    '9999px',
                    backgroundColor: i === active ? 'var(--color-primary-blue)' : 'var(--color-border-card)',
                    transition:      'all 0.25s',
                    border:          'none',
                    cursor:          'pointer'
                  }}
                />
              ))}
            </div>

            <button
              onClick={() => setActive(a => Math.min(2, a + 1))}
              disabled={active === 2}
              className="rounded-full p-1.5 border transition-colors"
              style={{
                borderColor:     'var(--color-border-card)',
                backgroundColor: 'var(--color-bg-card)',
                opacity:         active === 2 ? 0.3 : 1
              }}
            >
              <ChevronRight size={14} style={{ color: 'var(--color-text-secondary)' }} />
            </button>
          </div>
        </div>
      </div>
    )
  }
