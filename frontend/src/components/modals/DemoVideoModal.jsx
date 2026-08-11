import { useEffect } from 'react'
import { Video, X } from 'lucide-react'

export function DemoVideoModal({ isOpen, onClose }) {
  useEffect(() => {
    if (!isOpen) return
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [isOpen, onClose])

  if (!isOpen) return null

  const VIDEO_ID = '6TZZttQnAro'
  const embedUrl = [
    `https://www.youtube.com/embed/${VIDEO_ID}`,
    '?autoplay=1',
    '&rel=0',
    '&modestbranding=1',
    '&iv_load_policy=3',
    '&disablekb=0',
    '&fs=1',
    '&color=white',
    '&controls=1'
  ].join('')

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div
        className="absolute inset-0 backdrop-blur-sm"
        style={{ backgroundColor: 'rgba(0,0,0,0.75)' }}
        onClick={onClose}
      />

      <div
        className="relative w-full max-w-4xl overflow-hidden rounded-xl border animate-fade-slide"
        style={{
          backgroundColor: 'var(--color-bg-elevated)',
          borderColor:     'var(--color-border-card)',
          boxShadow:       '0 20px 60px rgba(0,0,0,0.55)'
        }}
      >
        <div
          className="flex items-center justify-between border-b px-5 py-3.5"
          style={{ borderColor: 'var(--color-border-card)' }}
        >
          <div className="flex items-center gap-2.5">
            <Video
              size={16}
              strokeWidth={1.75}
              style={{ color: 'var(--color-primary-blue)' }}
              aria-hidden="true"
            />
            <div>
              <h2 className="text-sm font-bold" style={{ color: 'var(--color-text-primary)' }}>
                Live Demonstration
              </h2>
              <p style={{ fontSize: '11px', color: 'var(--color-text-muted)' }}>
                sensor.py real mode on local network
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 transition-colors duration-150"
            style={{ color: 'var(--color-text-muted)' }}
            onMouseEnter={e => e.currentTarget.style.color = 'var(--color-text-primary)'}
            onMouseLeave={e => e.currentTarget.style.color = 'var(--color-text-muted)'}
            aria-label="Close demo video"
          >
            <X size={16} strokeWidth={1.75} />
          </button>
        </div>

        <div className="aspect-video w-full bg-black">
          <iframe
            src={embedUrl}
            className="h-full w-full border-0"
            allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
            allowFullScreen
            title="NIDS SOC Live Demo"
          />
        </div>
      </div>
    </div>
  )
}