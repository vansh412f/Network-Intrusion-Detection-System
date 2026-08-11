import { useSearchParams } from 'react-router-dom'
import { Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { CheckCircle, XCircle, Shield } from 'lucide-react'

export default function UnsubscribedPage() {
  const [searchParams] = useSearchParams()
  const success = searchParams.get('success') === 'true'
  const error   = searchParams.get('error')

  const isExpired = error === 'expired'
  const isInvalid = error === 'invalid'
  const isError   = isExpired || isInvalid

  return (
    <div
      className="min-h-screen flex flex-col items-center justify-center px-4"
      style={{ backgroundColor: 'var(--color-bg-page)' }}
    >
      <motion.div
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.16, 1, 0.3, 1] }}
        className="w-full max-w-md"
      >
        <div
          className="rounded-2xl border p-10 text-center"
          style={{
            backgroundColor: 'var(--color-bg-card)',
            borderColor:     'var(--color-border-card)'
          }}
        >
          {/* Icon */}
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, type: 'spring', stiffness: 200, damping: 18 }}
            className="flex items-center justify-center mx-auto mb-6"
            style={{
              width:           64,
              height:          64,
              borderRadius:    '50%',
              backgroundColor: isError ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)',
              border:          `1px solid ${isError ? 'rgba(239,68,68,0.2)' : 'rgba(16,185,129,0.2)'}`
            }}
          >
            {isError
              ? <XCircle size={32} strokeWidth={1.5} style={{ color: '#ef4444' }} />
              : <CheckCircle size={32} strokeWidth={1.5} style={{ color: '#10b981' }} />
            }
          </motion.div>

          {/* Title */}
          <h1
            className="text-xl font-bold mb-3"
            style={{ color: 'var(--color-text-primary)' }}
          >
            {isExpired ? 'Link Expired' : isInvalid ? 'Invalid Link' : 'Unsubscribed'}
          </h1>

          {/* Message */}
          <p
            className="leading-relaxed mb-8"
            style={{ fontSize: '14px', color: 'var(--color-text-secondary)' }}
          >
            {isExpired
              ? 'This unsubscribe link has expired. Links are valid for 30 days. Please use the link from a recent alert email.'
              : isInvalid
              ? 'This unsubscribe link is invalid. Please use the link from your alert email.'
              : 'You have been successfully unsubscribed from NIDS threat alert emails. You can re-enable notifications anytime from your profile.'
            }
          </p>

          {/* Actions */}
          <div className="flex flex-col gap-3">
            <Link
              to="/dashboard"
              className="rounded-xl py-2.5 text-sm font-semibold text-white transition-colors duration-150"
              style={{ backgroundColor: 'var(--color-primary-blue)' }}
            >
              Go to Dashboard
            </Link>
            <Link
              to="/profile"
              className="rounded-xl border py-2.5 text-sm font-medium transition-colors duration-150"
              style={{
                borderColor: 'var(--color-border-card)',
                color:       'var(--color-text-secondary)'
              }}
            >
              Manage Preferences
            </Link>
          </div>
        </div>

        {/* Footer brand */}
        <div className="flex items-center justify-center gap-2 mt-6">
          <Shield size={14} strokeWidth={1.75} style={{ color: 'var(--color-text-muted)' }} />
          <span style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>
            NIDS SOC Dashboard
          </span>
        </div>
      </motion.div>
    </div>
  )
}