import { useState } from 'react'
import { motion } from 'framer-motion'

export function FeatureCard({ icon: Icon, title, desc, accent, index, inView }) {
  const [hovered, setHovered] = useState(false)

  return (
    <motion.div
      initial={{ opacity: 0, y: 24 }}
      animate={inView ? { opacity: 1, y: 0 } : {}}
      transition={{ duration: 0.5, delay: index * 0.08 }}
      whileHover={{ y: -5 }}
      onHoverStart={() => setHovered(true)}
      onHoverEnd={() =>   setHovered(false)}
      className="relative rounded-xl border p-5 overflow-hidden cursor-default"
      style={{
        borderColor:     hovered ? `${accent}40` : 'var(--color-border-card)',
        backgroundColor: 'var(--color-bg-card)',
        transition:      'border-color 0.2s, box-shadow 0.2s',
        boxShadow:       hovered ? `0 8px 32px ${accent}18` : 'none'
      }}
    >
      <motion.div
        style={{
          position:        'absolute',
          left:            0,
          top:             '10%',
          bottom:          '10%',
          width:           '3px',
          borderRadius:    '0 3px 3px 0',
          backgroundColor: accent,
          transformOrigin: 'top'
        }}
        initial={{ scaleY: 0 }}
        animate={{ scaleY: hovered ? 1 : 0 }}
        transition={{ duration: 0.2 }}
      />

      <motion.div
        style={{
          position:        'absolute',
          inset:           0,
          background:      `radial-gradient(ellipse 60% 50% at 10% 50%, ${accent}08 0%, transparent 70%)`,
          pointerEvents:   'none'
        }}
        initial={{ opacity: 0 }}
        animate={{ opacity: hovered ? 1 : 0 }}
        transition={{ duration: 0.3 }}
      />

      <div className="flex items-center gap-3 mb-2">
        <motion.div
          className="flex h-9 w-9 items-center justify-center rounded-lg flex-shrink-0"
          style={{
            backgroundColor: `${accent}14`,
            border:          `1px solid ${accent}28`
          }}
          animate={{ scale: hovered ? 1.08 : 1, rotate: hovered ? 4 : 0 }}
          transition={{ type: 'spring', stiffness: 300, damping: 20 }}
        >
          <Icon size={16} strokeWidth={1.75} style={{ color: accent }} aria-hidden="true" />
        </motion.div>

        <h3 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>
          {title}
        </h3>
      </div>

      <p className="leading-relaxed" style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
        {desc}
      </p>
    </motion.div>
  )
}
