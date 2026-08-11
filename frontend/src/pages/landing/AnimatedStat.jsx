import { useEffect, useState } from 'react'
import { motion, useMotionValue, useTransform, animate } from 'framer-motion'

export function AnimatedStat({ value, suffix, label, accent, isString, index, inView }) {
  const mv      = useMotionValue(0)
  const display = useTransform(mv, v => {
    if (isString) return value
    if (suffix === '%') return v.toFixed(2)
    return Math.round(v)
  })
  const [rendered, setRendered] = useState(isString ? value : '0')

  useEffect(() => {
    if (!inView || isString) return
    const controls = animate(mv, parseFloat(value), {
      duration: 1.4,
      delay:    index * 0.1,
      ease:     [0.16, 1, 0.3, 1]
    })
    return controls.stop
  }, [inView, value, isString, index, mv])

  useEffect(() => {
    return display.on('change', v => setRendered(v))
  }, [display])

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, delay: index * 0.1 }}
      className="flex flex-col items-center gap-1.5 px-4 py-7 relative"
      style={{
        borderRight: index < 3 ? '1px solid var(--color-border-card)' : 'none'
      }}
    >
      <div
        style={{
          position:        'absolute',
          bottom:          0,
          left:            '20%',
          right:           '20%',
          height:          '2px',
          borderRadius:    '999px',
          backgroundColor: accent,
          opacity:         0.7
        }}
      />
      <span
        className="font-mono text-2xl font-bold"
        style={{ color: accent }}
      >
        {rendered}{suffix && !isString ? suffix : ''}
      </span>
      <span style={{ fontSize: '11px', color: 'var(--color-text-muted)', textAlign: 'center' }}>
        {label}
      </span>
    </motion.div>
  )
}
