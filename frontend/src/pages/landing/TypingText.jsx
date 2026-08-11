import { useEffect, useRef, useState } from 'react'

const MESSAGES = [
  'Monitoring network traffic...',
  'XGBoost model loaded — 99.85% accuracy',
  'WebSocket connection established...',
  'Sensor scanning for threats...'
]

export function TypingText() {
  const [text, setText] = useState('')
  const msgIndex = useRef(0)

  useEffect(() => {
    let charIndex = 0
    let typing    = true

    const tick = () => {
      const full = MESSAGES[msgIndex.current]
      if (typing) {
        charIndex++
        setText(full.slice(0, charIndex))
        if (charIndex >= full.length) {
          typing = false
          setTimeout(tick, 1800)
          return
        }
      } else {
        charIndex--
        setText(full.slice(0, charIndex))
        if (charIndex <= 0) {
          typing = true
          msgIndex.current = (msgIndex.current + 1) % MESSAGES.length
        }
      }
      setTimeout(tick, typing ? 55 : 28)
    }

    const t = setTimeout(tick, 400)
    return () => clearTimeout(t)
  }, [])

  return (
    <div
      className="inline-flex items-center gap-2 rounded-full border px-4 py-2"
      style={{
        borderColor:     'var(--color-border-card)',
        backgroundColor: 'var(--color-bg-card)'
      }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full animate-pulse-glow flex-shrink-0"
        style={{ backgroundColor: 'var(--color-live-green)' }}
      />
      <span className="font-mono" style={{ fontSize: '12px', color: 'var(--color-text-muted)', minWidth: '220px' }}>
        {text}
        <span className="animate-cursor-blink">|</span>
      </span>
    </div>
  )
}